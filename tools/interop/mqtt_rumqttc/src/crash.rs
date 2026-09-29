use std::error::Error;
use std::path::Path;
use std::time::Duration;

use rumqttc::v5;
use rumqttc::{Client, Event, Incoming, MqttOptions, QoS};

use super::{
    disconnect_v4, disconnect_v5, next_v4, next_v5, wait_v4_connack, wait_v4_puback,
    wait_v4_suback, wait_v5_connack, wait_v5_puback, wait_v5_suback,
};

const V4_CLIENT_ID: &str = "netz-rumqttc-v4-crash";
const V4_TOPIC: &str = "rumqttc/v4/crash-session";
const V4_PAYLOAD: &[u8] = b"v4-survives-broker-crash";
const V5_CLIENT_ID: &str = "netz-rumqttc-v5-crash";
const V5_TOPIC: &str = "rumqttc/v5/crash-session";
const V5_PAYLOAD: &[u8] = b"v5-survives-broker-crash";

pub fn prepare(port: u16) -> Result<(), Box<dyn Error>> {
    prepare_v4(port)?;
    prepare_v5(port)?;
    Ok(())
}

pub fn deliver_unacked(port: u16, packet_ids_path: &Path) -> Result<(), Box<dyn Error>> {
    let v4_packet_id = deliver_v4_unacked(port)?;
    let v5_packet_id = deliver_v5_unacked(port)?;
    std::fs::write(
        packet_ids_path,
        format!("v4_pkid={v4_packet_id}\nv5_pkid={v5_packet_id}\n"),
    )?;
    Ok(())
}

pub fn retry_and_ack(
    port: u16,
    expected_v4_packet_id: u16,
    expected_v5_packet_id: u16,
) -> Result<(), Box<dyn Error>> {
    retry_and_ack_v4(port, expected_v4_packet_id)?;
    retry_and_ack_v5(port, expected_v5_packet_id)?;
    Ok(())
}

pub fn verify_cleared(port: u16) -> Result<(), Box<dyn Error>> {
    verify_v4_cleared(port)?;
    verify_v5_cleared(port)?;
    Ok(())
}

fn prepare_v4(port: u16) -> Result<(), Box<dyn Error>> {
    let mut options = v4_options(V4_CLIENT_ID, port);
    options.set_clean_session(false);
    let (client, mut connection) = Client::new(options, 16);
    wait_v4_connack(&mut connection, false)?;
    client.subscribe(V4_TOPIC, QoS::AtLeastOnce)?;
    wait_v4_suback(&mut connection, QoS::AtLeastOnce)?;
    disconnect_v4(&client, &mut connection)?;

    let mut publisher_options = v4_options("netz-rumqttc-v4-crash-publisher", port);
    publisher_options.set_clean_session(true);
    let (publisher, mut publisher_connection) = Client::new(publisher_options, 16);
    wait_v4_connack(&mut publisher_connection, false)?;
    publisher.publish(V4_TOPIC, QoS::AtLeastOnce, false, V4_PAYLOAD)?;
    wait_v4_puback(&mut publisher_connection)?;
    disconnect_v4(&publisher, &mut publisher_connection)?;
    Ok(())
}

fn deliver_v4_unacked(port: u16) -> Result<u16, Box<dyn Error>> {
    let mut options = v4_options(V4_CLIENT_ID, port);
    options.set_clean_session(false);
    options.set_manual_acks(true);
    let (_client, mut connection) = Client::new(options, 16);
    wait_v4_connack(&mut connection, true)?;
    let publish = wait_v4_manual_publish(&mut connection, false)?;
    Ok(publish.pkid)
}

fn retry_and_ack_v4(port: u16, expected_packet_id: u16) -> Result<(), Box<dyn Error>> {
    let mut options = v4_options(V4_CLIENT_ID, port);
    options.set_clean_session(false);
    options.set_manual_acks(true);
    let (client, mut connection) = Client::new(options, 16);
    wait_v4_connack(&mut connection, true)?;
    let publish = wait_v4_manual_publish(&mut connection, true)?;
    if publish.pkid != expected_packet_id {
        return Err(format!(
            "rumqttc v4 restored Packet Identifier changed: got={} expected={}",
            publish.pkid, expected_packet_id
        )
        .into());
    }
    client.ack(&publish)?;
    wait_v4_outgoing_puback(&mut connection, expected_packet_id)?;
    send_v4_barrier(&client, &mut connection)?;
    disconnect_v4(&client, &mut connection)?;
    Ok(())
}

fn verify_v4_cleared(port: u16) -> Result<(), Box<dyn Error>> {
    let mut options = v4_options(V4_CLIENT_ID, port);
    options.set_clean_session(false);
    let (client, mut connection) = Client::new(options, 16);
    wait_v4_connack(&mut connection, true)?;
    send_v4_barrier(&client, &mut connection)?;
    disconnect_v4(&client, &mut connection)?;
    Ok(())
}

fn wait_v4_manual_publish(
    connection: &mut rumqttc::Connection,
    expected_dup: bool,
) -> Result<rumqttc::Publish, Box<dyn Error>> {
    loop {
        match next_v4(connection)? {
            Event::Incoming(Incoming::Publish(publish)) => {
                if publish.topic != V4_TOPIC
                    || publish.payload.as_ref() != V4_PAYLOAD
                    || publish.qos != QoS::AtLeastOnce
                    || publish.retain
                    || publish.dup != expected_dup
                    || publish.pkid == 0
                {
                    return Err(format!("rumqttc v4 unexpected crash PUBLISH: {publish:?}").into());
                }
                return Ok(publish);
            }
            Event::Outgoing(rumqttc::Outgoing::PubAck(_)) => {
                return Err("rumqttc v4 sent PUBACK with manual ACK enabled".into());
            }
            _ => {}
        }
    }
}

fn wait_v4_outgoing_puback(
    connection: &mut rumqttc::Connection,
    expected_packet_id: u16,
) -> Result<(), Box<dyn Error>> {
    loop {
        match next_v4(connection)? {
            Event::Outgoing(rumqttc::Outgoing::PubAck(packet_id)) => {
                if packet_id != expected_packet_id {
                    return Err(format!(
                        "rumqttc v4 acknowledged Packet Identifier {packet_id}, expected {expected_packet_id}"
                    )
                    .into());
                }
                return Ok(());
            }
            Event::Incoming(Incoming::Publish(_)) => {
                return Err("rumqttc v4 duplicate PUBLISH before manual PUBACK".into());
            }
            _ => {}
        }
    }
}

fn send_v4_barrier(
    client: &Client,
    connection: &mut rumqttc::Connection,
) -> Result<(), Box<dyn Error>> {
    client.publish(
        "rumqttc/v4/crash-barrier",
        QoS::AtLeastOnce,
        false,
        b"barrier".as_slice(),
    )?;
    wait_v4_puback(connection)
}

fn prepare_v5(port: u16) -> Result<(), Box<dyn Error>> {
    use v5::mqttbytes::QoS as V5QoS;

    let mut options = v5_options(V5_CLIENT_ID, port);
    options.set_clean_start(false);
    options.set_session_expiry_interval(Some(60));
    let (client, mut connection) = v5::Client::new(options, 16);
    wait_v5_connack(&mut connection, false)?;
    client.subscribe(V5_TOPIC, V5QoS::AtLeastOnce)?;
    wait_v5_suback(&mut connection, V5QoS::AtLeastOnce)?;
    disconnect_v5(&client, &mut connection)?;

    let mut publisher_options = v5_options("netz-rumqttc-v5-crash-publisher", port);
    publisher_options.set_clean_start(true);
    let (publisher, mut publisher_connection) = v5::Client::new(publisher_options, 16);
    wait_v5_connack(&mut publisher_connection, false)?;
    publisher.publish(V5_TOPIC, V5QoS::AtLeastOnce, false, V5_PAYLOAD)?;
    wait_v5_puback(&mut publisher_connection)?;
    disconnect_v5(&publisher, &mut publisher_connection)?;
    Ok(())
}

fn deliver_v5_unacked(port: u16) -> Result<u16, Box<dyn Error>> {
    let mut options = v5_options(V5_CLIENT_ID, port);
    options.set_clean_start(false);
    options.set_session_expiry_interval(Some(60));
    options.set_manual_acks(true);
    let (_client, mut connection) = v5::Client::new(options, 16);
    wait_v5_connack(&mut connection, true)?;
    let publish = wait_v5_manual_publish(&mut connection, false)?;
    Ok(publish.pkid)
}

fn retry_and_ack_v5(port: u16, expected_packet_id: u16) -> Result<(), Box<dyn Error>> {
    let mut options = v5_options(V5_CLIENT_ID, port);
    options.set_clean_start(false);
    options.set_session_expiry_interval(Some(60));
    options.set_manual_acks(true);
    let (client, mut connection) = v5::Client::new(options, 16);
    wait_v5_connack(&mut connection, true)?;
    let publish = wait_v5_manual_publish(&mut connection, true)?;
    if publish.pkid != expected_packet_id {
        return Err(format!(
            "rumqttc v5 restored Packet Identifier changed: got={} expected={}",
            publish.pkid, expected_packet_id
        )
        .into());
    }
    client.ack(&publish)?;
    wait_v5_outgoing_puback(&mut connection, expected_packet_id)?;
    send_v5_barrier(&client, &mut connection)?;
    disconnect_v5(&client, &mut connection)?;
    Ok(())
}

fn verify_v5_cleared(port: u16) -> Result<(), Box<dyn Error>> {
    let mut options = v5_options(V5_CLIENT_ID, port);
    options.set_clean_start(false);
    options.set_session_expiry_interval(Some(60));
    let (client, mut connection) = v5::Client::new(options, 16);
    wait_v5_connack(&mut connection, true)?;
    send_v5_barrier(&client, &mut connection)?;
    disconnect_v5(&client, &mut connection)?;
    Ok(())
}

fn wait_v5_manual_publish(
    connection: &mut v5::Connection,
    expected_dup: bool,
) -> Result<v5::mqttbytes::v5::Publish, Box<dyn Error>> {
    use v5::mqttbytes::QoS as V5QoS;

    loop {
        match next_v5(connection)? {
            v5::Event::Incoming(v5::Incoming::Publish(publish)) => {
                if publish.topic.as_ref() != V5_TOPIC.as_bytes()
                    || publish.payload.as_ref() != V5_PAYLOAD
                    || publish.qos != V5QoS::AtLeastOnce
                    || publish.retain
                    || publish.dup != expected_dup
                    || publish.pkid == 0
                {
                    return Err(format!("rumqttc v5 unexpected crash PUBLISH: {publish:?}").into());
                }
                return Ok(publish);
            }
            v5::Event::Outgoing(rumqttc::Outgoing::PubAck(_)) => {
                return Err("rumqttc v5 sent PUBACK with manual ACK enabled".into());
            }
            _ => {}
        }
    }
}

fn wait_v5_outgoing_puback(
    connection: &mut v5::Connection,
    expected_packet_id: u16,
) -> Result<(), Box<dyn Error>> {
    loop {
        match next_v5(connection)? {
            v5::Event::Outgoing(rumqttc::Outgoing::PubAck(packet_id)) => {
                if packet_id != expected_packet_id {
                    return Err(format!(
                        "rumqttc v5 acknowledged Packet Identifier {packet_id}, expected {expected_packet_id}"
                    )
                    .into());
                }
                return Ok(());
            }
            v5::Event::Incoming(v5::Incoming::Publish(_)) => {
                return Err("rumqttc v5 duplicate PUBLISH before manual PUBACK".into());
            }
            _ => {}
        }
    }
}

fn send_v5_barrier(
    client: &v5::Client,
    connection: &mut v5::Connection,
) -> Result<(), Box<dyn Error>> {
    client.publish(
        "rumqttc/v5/crash-barrier",
        v5::mqttbytes::QoS::AtLeastOnce,
        false,
        b"barrier".as_slice(),
    )?;
    wait_v5_puback(connection)
}

fn v4_options(client_id: &str, port: u16) -> MqttOptions {
    let mut options = MqttOptions::new(client_id, "127.0.0.1", port);
    options.set_keep_alive(Duration::from_secs(5));
    options
}

fn v5_options(client_id: &str, port: u16) -> v5::MqttOptions {
    let mut options = v5::MqttOptions::new(client_id, "127.0.0.1", port);
    options.set_keep_alive(Duration::from_secs(5));
    options
}
