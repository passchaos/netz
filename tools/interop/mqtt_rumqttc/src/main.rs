use std::error::Error;
use std::time::Duration;

use rumqttc::v5;
use rumqttc::v5::mqttbytes::v5::PublishProperties;
use rumqttc::{Client, Connection, Event, Incoming, MqttOptions, QoS};

const TIMEOUT: Duration = Duration::from_secs(10);

fn next_v4(connection: &mut Connection) -> Result<Event, Box<dyn Error>> {
    let event = connection
        .recv_timeout(TIMEOUT)
        .map_err(|error| std::io::Error::other(format!("rumqttc v4 receive failed: {error:?}")))?;
    Ok(event?)
}

fn wait_v4_connack(
    connection: &mut Connection,
    expected_session_present: bool,
) -> Result<(), Box<dyn Error>> {
    loop {
        if let Event::Incoming(Incoming::ConnAck(connack)) = next_v4(connection)? {
            if connack.code != rumqttc::ConnectReturnCode::Success
                || connack.session_present != expected_session_present
            {
                return Err(format!(
                    "rumqttc v4 unexpected CONNACK: code={:?} session_present={} expected_session_present={}",
                    connack.code, connack.session_present, expected_session_present
                )
                .into());
            }
            return Ok(());
        }
    }
}

fn wait_v4_suback(connection: &mut Connection, expected_qos: QoS) -> Result<(), Box<dyn Error>> {
    loop {
        if let Event::Incoming(Incoming::SubAck(suback)) = next_v4(connection)? {
            let expected = vec![rumqttc::SubscribeReasonCode::Success(expected_qos)];
            if suback.return_codes != expected {
                return Err(
                    format!("rumqttc v4 unexpected SUBACK: {:?}", suback.return_codes).into(),
                );
            }
            return Ok(());
        }
    }
}

fn wait_v4_publish(
    connection: &mut Connection,
    topic: &str,
    payload: &[u8],
    qos: QoS,
    retain: bool,
    require_publish_completion: bool,
) -> Result<(), Box<dyn Error>> {
    let mut delivered = false;
    let mut completed = !require_publish_completion || qos == QoS::AtMostOnce;
    let mut delivery_acked = qos == QoS::AtMostOnce;
    while !delivered || !completed || !delivery_acked {
        match next_v4(connection)? {
            Event::Incoming(Incoming::Publish(publish)) => {
                if publish.topic != topic || publish.payload.as_ref() != payload {
                    return Err(format!(
                        "rumqttc v4 unexpected PUBLISH: topic={} payload={:?}",
                        publish.topic, publish.payload
                    )
                    .into());
                }
                if delivered {
                    return Err("rumqttc v4 duplicate PUBLISH".into());
                }
                assert_eq!(publish.qos, qos);
                assert_eq!(publish.retain, retain);
                delivered = true;
            }
            Event::Incoming(Incoming::PubAck(_)) if qos == QoS::AtLeastOnce => {
                completed = true;
            }
            Event::Incoming(Incoming::PubComp(_)) if qos == QoS::ExactlyOnce => {
                completed = true;
            }
            Event::Outgoing(rumqttc::Outgoing::PubAck(_)) if qos == QoS::AtLeastOnce => {
                delivery_acked = true;
            }
            Event::Outgoing(rumqttc::Outgoing::PubComp(_)) if qos == QoS::ExactlyOnce => {
                delivery_acked = true;
            }
            _ => {}
        }
    }
    Ok(())
}

fn wait_v4_puback(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
    loop {
        match next_v4(connection)? {
            Event::Incoming(Incoming::PubAck(_)) => return Ok(()),
            Event::Incoming(Incoming::Publish(_)) => {
                return Err("rumqttc v4 publisher received unexpected PUBLISH".into());
            }
            _ => {}
        }
    }
}

fn disconnect_v4(client: &Client, connection: &mut Connection) -> Result<(), Box<dyn Error>> {
    client.disconnect()?;
    loop {
        match next_v4(connection)? {
            Event::Outgoing(rumqttc::Outgoing::Disconnect) => return Ok(()),
            Event::Incoming(Incoming::Publish(_)) => {
                return Err("rumqttc v4 duplicate PUBLISH before disconnect".into());
            }
            _ => {}
        }
    }
}

fn run_v4(port: u16) -> Result<(), Box<dyn Error>> {
    let client_id = "netz-rumqttc-v4";
    let topic = "rumqttc/v4/live";
    let retained_topic = "rumqttc/v4/retained";
    let session_topic = "rumqttc/v4/session";
    let session_payload = b"v4-offline-qos1";
    let mut options = MqttOptions::new(client_id, "127.0.0.1", port);
    options.set_keep_alive(Duration::from_secs(5));
    options.set_clean_session(false);
    let (client, mut connection) = Client::new(options, 16);

    wait_v4_connack(&mut connection, false)?;
    client.subscribe(session_topic, QoS::AtLeastOnce)?;
    wait_v4_suback(&mut connection, QoS::AtLeastOnce)?;
    client.subscribe(topic, QoS::ExactlyOnce)?;
    wait_v4_suback(&mut connection, QoS::ExactlyOnce)?;

    for (qos, payload) in [
        (QoS::AtMostOnce, b"v4-qos0".as_slice()),
        (QoS::AtLeastOnce, b"v4-qos1".as_slice()),
        (QoS::ExactlyOnce, b"v4-qos2".as_slice()),
    ] {
        client.publish(topic, qos, false, payload)?;
        wait_v4_publish(&mut connection, topic, payload, qos, false, true)?;
    }

    client.publish(retained_topic, QoS::AtLeastOnce, true, "v4-retained")?;
    loop {
        match next_v4(&mut connection)? {
            Event::Incoming(Incoming::PubAck(_)) => break,
            Event::Incoming(Incoming::Publish(_)) => {
                return Err("rumqttc v4 unexpected PUBLISH before retained PUBACK".into());
            }
            _ => {}
        }
    }
    client.subscribe(retained_topic, QoS::ExactlyOnce)?;
    wait_v4_suback(&mut connection, QoS::ExactlyOnce)?;
    wait_v4_publish(
        &mut connection,
        retained_topic,
        b"v4-retained",
        QoS::AtLeastOnce,
        true,
        false,
    )?;

    disconnect_v4(&client, &mut connection)?;

    let mut publisher_options = MqttOptions::new("netz-rumqttc-v4-publisher", "127.0.0.1", port);
    publisher_options.set_keep_alive(Duration::from_secs(5));
    publisher_options.set_clean_session(true);
    let (publisher, mut publisher_connection) = Client::new(publisher_options, 16);
    wait_v4_connack(&mut publisher_connection, false)?;
    publisher.publish(
        session_topic,
        QoS::AtLeastOnce,
        false,
        session_payload.as_slice(),
    )?;
    wait_v4_puback(&mut publisher_connection)?;
    disconnect_v4(&publisher, &mut publisher_connection)?;

    let mut resumed_options = MqttOptions::new(client_id, "127.0.0.1", port);
    resumed_options.set_keep_alive(Duration::from_secs(5));
    resumed_options.set_clean_session(false);
    let (resumed, mut resumed_connection) = Client::new(resumed_options, 16);
    wait_v4_connack(&mut resumed_connection, true)?;
    wait_v4_publish(
        &mut resumed_connection,
        session_topic,
        session_payload,
        QoS::AtLeastOnce,
        false,
        false,
    )?;
    disconnect_v4(&resumed, &mut resumed_connection)?;
    Ok(())
}

fn next_v5(connection: &mut v5::Connection) -> Result<v5::Event, Box<dyn Error>> {
    let event = connection
        .recv_timeout(TIMEOUT)
        .map_err(|error| std::io::Error::other(format!("rumqttc v5 receive failed: {error:?}")))?;
    Ok(event?)
}

fn wait_v5_connack(
    connection: &mut v5::Connection,
    expected_session_present: bool,
) -> Result<(), Box<dyn Error>> {
    loop {
        if let v5::Event::Incoming(v5::Incoming::ConnAck(connack)) = next_v5(connection)? {
            if connack.code != v5::mqttbytes::v5::ConnectReturnCode::Success
                || connack.session_present != expected_session_present
            {
                return Err(format!(
                    "rumqttc v5 unexpected CONNACK: code={:?} session_present={} expected_session_present={}",
                    connack.code, connack.session_present, expected_session_present
                )
                .into());
            }
            return Ok(());
        }
    }
}

fn wait_v5_suback(
    connection: &mut v5::Connection,
    expected_qos: v5::mqttbytes::QoS,
) -> Result<(), Box<dyn Error>> {
    loop {
        if let v5::Event::Incoming(v5::Incoming::SubAck(suback)) = next_v5(connection)? {
            let expected = vec![v5::mqttbytes::v5::SubscribeReasonCode::Success(
                expected_qos,
            )];
            if suback.return_codes != expected {
                return Err(
                    format!("rumqttc v5 unexpected SUBACK: {:?}", suback.return_codes).into(),
                );
            }
            return Ok(());
        }
    }
}

fn wait_v5_publish(
    connection: &mut v5::Connection,
    topic: &str,
    payload: &[u8],
    qos: v5::mqttbytes::QoS,
    retain: bool,
    expected_properties: bool,
    require_publish_completion: bool,
) -> Result<(), Box<dyn Error>> {
    let mut delivered = false;
    let mut completed = !require_publish_completion || qos == v5::mqttbytes::QoS::AtMostOnce;
    let mut delivery_acked = qos == v5::mqttbytes::QoS::AtMostOnce;
    while !delivered || !completed || !delivery_acked {
        match next_v5(connection)? {
            v5::Event::Incoming(v5::Incoming::Publish(publish)) => {
                if publish.topic.as_ref() != topic.as_bytes() || publish.payload.as_ref() != payload
                {
                    return Err(format!(
                        "rumqttc v5 unexpected PUBLISH: topic={:?} payload={:?}",
                        publish.topic, publish.payload
                    )
                    .into());
                }
                if delivered {
                    return Err("rumqttc v5 duplicate PUBLISH".into());
                }
                assert_eq!(publish.qos, qos);
                assert_eq!(publish.retain, retain);
                if expected_properties {
                    let properties = publish.properties.expect("publish properties");
                    assert_eq!(
                        properties.response_topic.as_deref(),
                        Some("rumqttc/v5/reply"),
                    );
                    assert_eq!(
                        properties.correlation_data.as_deref(),
                        Some(b"correlation-42".as_slice()),
                    );
                    assert_eq!(
                        properties.user_properties,
                        vec![("source".into(), "rumqttc".into())],
                    );
                }
                delivered = true;
            }
            v5::Event::Incoming(v5::Incoming::PubAck(_))
                if qos == v5::mqttbytes::QoS::AtLeastOnce =>
            {
                completed = true;
            }
            v5::Event::Incoming(v5::Incoming::PubComp(_))
                if qos == v5::mqttbytes::QoS::ExactlyOnce =>
            {
                completed = true;
            }
            v5::Event::Outgoing(rumqttc::Outgoing::PubAck(_))
                if qos == v5::mqttbytes::QoS::AtLeastOnce =>
            {
                delivery_acked = true;
            }
            v5::Event::Outgoing(rumqttc::Outgoing::PubComp(_))
                if qos == v5::mqttbytes::QoS::ExactlyOnce =>
            {
                delivery_acked = true;
            }
            _ => {}
        }
    }
    Ok(())
}

fn wait_v5_puback(connection: &mut v5::Connection) -> Result<(), Box<dyn Error>> {
    loop {
        match next_v5(connection)? {
            v5::Event::Incoming(v5::Incoming::PubAck(_)) => return Ok(()),
            v5::Event::Incoming(v5::Incoming::Publish(_)) => {
                return Err("rumqttc v5 publisher received unexpected PUBLISH".into());
            }
            _ => {}
        }
    }
}

fn disconnect_v5(
    client: &v5::Client,
    connection: &mut v5::Connection,
) -> Result<(), Box<dyn Error>> {
    client.disconnect()?;
    loop {
        match next_v5(connection)? {
            v5::Event::Outgoing(rumqttc::Outgoing::Disconnect) => return Ok(()),
            v5::Event::Incoming(v5::Incoming::Publish(_)) => {
                return Err("rumqttc v5 duplicate PUBLISH before disconnect".into());
            }
            _ => {}
        }
    }
}

fn run_v5(port: u16) -> Result<(), Box<dyn Error>> {
    use v5::mqttbytes::QoS as V5QoS;

    let client_id = "netz-rumqttc-v5";
    let topic = "rumqttc/v5/live";
    let retained_topic = "rumqttc/v5/retained";
    let session_topic = "rumqttc/v5/session";
    let session_payload = b"v5-offline-qos1";
    let mut options = v5::MqttOptions::new(client_id, "127.0.0.1", port);
    options.set_keep_alive(Duration::from_secs(5));
    options.set_clean_start(false);
    options.set_session_expiry_interval(Some(60));
    let (client, mut connection) = v5::Client::new(options, 16);

    wait_v5_connack(&mut connection, false)?;
    client.subscribe(session_topic, V5QoS::AtLeastOnce)?;
    wait_v5_suback(&mut connection, V5QoS::AtLeastOnce)?;
    client.subscribe(topic, V5QoS::ExactlyOnce)?;
    wait_v5_suback(&mut connection, V5QoS::ExactlyOnce)?;

    for (qos, payload) in [
        (V5QoS::AtMostOnce, b"v5-qos0".as_slice()),
        (V5QoS::AtLeastOnce, b"v5-qos1".as_slice()),
        (V5QoS::ExactlyOnce, b"v5-qos2".as_slice()),
    ] {
        client.publish(topic, qos, false, payload)?;
        wait_v5_publish(&mut connection, topic, payload, qos, false, false, true)?;
    }

    let properties = PublishProperties {
        response_topic: Some("rumqttc/v5/reply".into()),
        correlation_data: Some(b"correlation-42".to_vec().into()),
        user_properties: vec![("source".into(), "rumqttc".into())],
        ..Default::default()
    };
    client.publish_with_properties(
        topic,
        V5QoS::AtLeastOnce,
        false,
        "v5-properties",
        properties,
    )?;
    wait_v5_publish(
        &mut connection,
        topic,
        b"v5-properties",
        V5QoS::AtLeastOnce,
        false,
        true,
        true,
    )?;

    client.publish(retained_topic, V5QoS::AtLeastOnce, true, "v5-retained")?;
    loop {
        match next_v5(&mut connection)? {
            v5::Event::Incoming(v5::Incoming::PubAck(_)) => break,
            v5::Event::Incoming(v5::Incoming::Publish(_)) => {
                return Err("rumqttc v5 unexpected PUBLISH before retained PUBACK".into());
            }
            _ => {}
        }
    }
    client.subscribe(retained_topic, V5QoS::ExactlyOnce)?;
    wait_v5_suback(&mut connection, V5QoS::ExactlyOnce)?;
    wait_v5_publish(
        &mut connection,
        retained_topic,
        b"v5-retained",
        V5QoS::AtLeastOnce,
        true,
        false,
        false,
    )?;

    disconnect_v5(&client, &mut connection)?;

    let mut publisher_options =
        v5::MqttOptions::new("netz-rumqttc-v5-publisher", "127.0.0.1", port);
    publisher_options.set_keep_alive(Duration::from_secs(5));
    publisher_options.set_clean_start(true);
    let (publisher, mut publisher_connection) = v5::Client::new(publisher_options, 16);
    wait_v5_connack(&mut publisher_connection, false)?;
    publisher.publish(
        session_topic,
        V5QoS::AtLeastOnce,
        false,
        session_payload.as_slice(),
    )?;
    wait_v5_puback(&mut publisher_connection)?;
    disconnect_v5(&publisher, &mut publisher_connection)?;

    let mut resumed_options = v5::MqttOptions::new(client_id, "127.0.0.1", port);
    resumed_options.set_keep_alive(Duration::from_secs(5));
    resumed_options.set_clean_start(false);
    resumed_options.set_session_expiry_interval(Some(60));
    let (resumed, mut resumed_connection) = v5::Client::new(resumed_options, 16);
    wait_v5_connack(&mut resumed_connection, true)?;
    wait_v5_publish(
        &mut resumed_connection,
        session_topic,
        session_payload,
        V5QoS::AtLeastOnce,
        false,
        false,
        false,
    )?;
    disconnect_v5(&resumed, &mut resumed_connection)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let port: u16 = std::env::args().nth(1).ok_or("missing port")?.parse()?;
    run_v4(port)?;
    run_v5(port)?;
    println!(
        "rumqttc client interop passed: rumqttc=0.25.1 protocols=mqtt311,mqtt5 qos=0,1,2 retained=true single-delivery=true automatic-ack=true response-topic=true correlation-data=true user-property=true session-resume=true offline-qos1=true client_io=rumqttc-tokio server_io=zio-std-io"
    );
    Ok(())
}
