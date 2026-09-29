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
const V4_QOS1_TOPIC: &str = "rumqttc/v4/crash-session/qos1";
const V4_QOS1_PAYLOAD: &[u8] = b"v4-qos1-survives-broker-crash";
const V4_QOS2_TOPIC: &str = "rumqttc/v4/crash-session/qos2";
const V4_QOS2_PAYLOAD: &[u8] = b"v4-qos2-survives-broker-crash";
const V5_CLIENT_ID: &str = "netz-rumqttc-v5-crash";
const V5_QOS1_TOPIC: &str = "rumqttc/v5/crash-session/qos1";
const V5_QOS1_PAYLOAD: &[u8] = b"v5-qos1-survives-broker-crash";
const V5_QOS2_TOPIC: &str = "rumqttc/v5/crash-session/qos2";
const V5_QOS2_PAYLOAD: &[u8] = b"v5-qos2-survives-broker-crash";

struct PacketIds {
    qos1: u16,
    qos2: u16,
}

pub fn prepare(port: u16) -> Result<(), Box<dyn Error>> {
    prepare_v4(port)?;
    prepare_v5(port)?;
    Ok(())
}

pub fn deliver_unacked(port: u16, packet_ids_path: &Path) -> Result<(), Box<dyn Error>> {
    let v4 = deliver_v4_unacked(port)?;
    let v5 = deliver_v5_unacked(port)?;
    std::fs::write(
        packet_ids_path,
        format!(
            "v4_qos1_pkid={}\nv4_qos2_pkid={}\nv5_qos1_pkid={}\nv5_qos2_pkid={}\n",
            v4.qos1, v4.qos2, v5.qos1, v5.qos2
        ),
    )?;
    Ok(())
}

pub fn retry_and_ack(
    port: u16,
    v4_qos1: u16,
    v4_qos2: u16,
    v5_qos1: u16,
    v5_qos2: u16,
) -> Result<(), Box<dyn Error>> {
    retry_and_ack_v4(
        port,
        PacketIds {
            qos1: v4_qos1,
            qos2: v4_qos2,
        },
    )?;
    retry_and_ack_v5(
        port,
        PacketIds {
            qos1: v5_qos1,
            qos2: v5_qos2,
        },
    )?;
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
    client.subscribe(V4_QOS1_TOPIC, QoS::AtLeastOnce)?;
    wait_v4_suback(&mut connection, QoS::AtLeastOnce)?;
    client.subscribe(V4_QOS2_TOPIC, QoS::ExactlyOnce)?;
    wait_v4_suback(&mut connection, QoS::ExactlyOnce)?;
    disconnect_v4(&client, &mut connection)?;

    let mut options = v4_options("netz-rumqttc-v4-crash-publisher", port);
    options.set_clean_session(true);
    let (publisher, mut connection) = Client::new(options, 16);
    wait_v4_connack(&mut connection, false)?;
    publisher.publish(V4_QOS1_TOPIC, QoS::AtLeastOnce, false, V4_QOS1_PAYLOAD)?;
    wait_v4_puback(&mut connection)?;
    publisher.publish(V4_QOS2_TOPIC, QoS::ExactlyOnce, false, V4_QOS2_PAYLOAD)?;
    wait_v4_pubcomp(&mut connection)?;
    disconnect_v4(&publisher, &mut connection)?;
    Ok(())
}

fn deliver_v4_unacked(port: u16) -> Result<PacketIds, Box<dyn Error>> {
    let mut options = v4_options(V4_CLIENT_ID, port);
    options.set_clean_session(false);
    options.set_manual_acks(true);
    let (_client, mut connection) = Client::new(options, 16);
    wait_v4_connack(&mut connection, true)?;
    let (qos1, qos2) = wait_v4_manual_publishes(&mut connection, false)?;
    Ok(PacketIds {
        qos1: qos1.pkid,
        qos2: qos2.pkid,
    })
}

fn retry_and_ack_v4(port: u16, expected: PacketIds) -> Result<(), Box<dyn Error>> {
    let mut options = v4_options(V4_CLIENT_ID, port);
    options.set_clean_session(false);
    options.set_manual_acks(true);
    let (client, mut connection) = Client::new(options, 16);
    wait_v4_connack(&mut connection, true)?;
    let (qos1, qos2) = wait_v4_manual_publishes(&mut connection, true)?;
    require_packet_ids("v4", qos1.pkid, qos2.pkid, &expected)?;
    client.ack(&qos1)?;
    client.ack(&qos2)?;
    wait_v4_completion(&mut connection, &expected)?;
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

fn wait_v4_manual_publishes(
    connection: &mut rumqttc::Connection,
    expected_dup: bool,
) -> Result<(rumqttc::Publish, rumqttc::Publish), Box<dyn Error>> {
    let mut qos1 = None;
    let mut qos2 = None;
    while qos1.is_none() || qos2.is_none() {
        match next_v4(connection)? {
            Event::Incoming(Incoming::Publish(publish)) => {
                if publish.retain || publish.dup != expected_dup || publish.pkid == 0 {
                    return Err(format!("rumqttc v4 unexpected crash PUBLISH: {publish:?}").into());
                }
                if publish.topic == V4_QOS1_TOPIC
                    && publish.payload.as_ref() == V4_QOS1_PAYLOAD
                    && publish.qos == QoS::AtLeastOnce
                    && qos1.is_none()
                {
                    qos1 = Some(publish);
                } else if publish.topic == V4_QOS2_TOPIC
                    && publish.payload.as_ref() == V4_QOS2_PAYLOAD
                    && publish.qos == QoS::ExactlyOnce
                    && qos2.is_none()
                {
                    qos2 = Some(publish);
                } else {
                    return Err(format!(
                        "rumqttc v4 unexpected or duplicate crash PUBLISH: {publish:?}"
                    )
                    .into());
                }
            }
            Event::Outgoing(rumqttc::Outgoing::PubAck(_))
            | Event::Outgoing(rumqttc::Outgoing::PubRec(_)) => {
                return Err("rumqttc v4 sent acknowledgement with manual ACK enabled".into());
            }
            _ => {}
        }
    }
    Ok((qos1.unwrap(), qos2.unwrap()))
}

fn wait_v4_completion(
    connection: &mut rumqttc::Connection,
    expected: &PacketIds,
) -> Result<(), Box<dyn Error>> {
    let mut puback = false;
    let mut pubrec = false;
    let mut pubrel = false;
    let mut pubcomp = false;
    while !puback || !pubrec || !pubrel || !pubcomp {
        match next_v4(connection)? {
            Event::Outgoing(rumqttc::Outgoing::PubAck(packet_id)) => {
                require_once("v4 PUBACK", packet_id, expected.qos1, &mut puback)?;
            }
            Event::Outgoing(rumqttc::Outgoing::PubRec(packet_id)) => {
                require_once("v4 PUBREC", packet_id, expected.qos2, &mut pubrec)?;
            }
            Event::Incoming(Incoming::PubRel(packet)) => {
                require_once("v4 PUBREL", packet.pkid, expected.qos2, &mut pubrel)?;
            }
            Event::Outgoing(rumqttc::Outgoing::PubComp(packet_id)) => {
                require_once("v4 PUBCOMP", packet_id, expected.qos2, &mut pubcomp)?;
            }
            Event::Incoming(Incoming::Publish(_)) => {
                return Err("rumqttc v4 duplicate PUBLISH during acknowledgement".into());
            }
            _ => {}
        }
    }
    Ok(())
}

fn wait_v4_pubcomp(connection: &mut rumqttc::Connection) -> Result<(), Box<dyn Error>> {
    loop {
        match next_v4(connection)? {
            Event::Incoming(Incoming::PubComp(_)) => return Ok(()),
            Event::Incoming(Incoming::Publish(_)) => {
                return Err("rumqttc v4 publisher received unexpected PUBLISH".into());
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
    client.subscribe(V5_QOS1_TOPIC, V5QoS::AtLeastOnce)?;
    wait_v5_suback(&mut connection, V5QoS::AtLeastOnce)?;
    client.subscribe(V5_QOS2_TOPIC, V5QoS::ExactlyOnce)?;
    wait_v5_suback(&mut connection, V5QoS::ExactlyOnce)?;
    disconnect_v5(&client, &mut connection)?;

    let mut options = v5_options("netz-rumqttc-v5-crash-publisher", port);
    options.set_clean_start(true);
    let (publisher, mut connection) = v5::Client::new(options, 16);
    wait_v5_connack(&mut connection, false)?;
    publisher.publish(V5_QOS1_TOPIC, V5QoS::AtLeastOnce, false, V5_QOS1_PAYLOAD)?;
    wait_v5_puback(&mut connection)?;
    publisher.publish(V5_QOS2_TOPIC, V5QoS::ExactlyOnce, false, V5_QOS2_PAYLOAD)?;
    wait_v5_pubcomp(&mut connection)?;
    disconnect_v5(&publisher, &mut connection)?;
    Ok(())
}

fn deliver_v5_unacked(port: u16) -> Result<PacketIds, Box<dyn Error>> {
    let mut options = v5_options(V5_CLIENT_ID, port);
    options.set_clean_start(false);
    options.set_session_expiry_interval(Some(60));
    options.set_manual_acks(true);
    let (_client, mut connection) = v5::Client::new(options, 16);
    wait_v5_connack(&mut connection, true)?;
    let (qos1, qos2) = wait_v5_manual_publishes(&mut connection, false)?;
    Ok(PacketIds {
        qos1: qos1.pkid,
        qos2: qos2.pkid,
    })
}

fn retry_and_ack_v5(port: u16, expected: PacketIds) -> Result<(), Box<dyn Error>> {
    let mut options = v5_options(V5_CLIENT_ID, port);
    options.set_clean_start(false);
    options.set_session_expiry_interval(Some(60));
    options.set_manual_acks(true);
    let (client, mut connection) = v5::Client::new(options, 16);
    wait_v5_connack(&mut connection, true)?;
    let (qos1, qos2) = wait_v5_manual_publishes(&mut connection, true)?;
    require_packet_ids("v5", qos1.pkid, qos2.pkid, &expected)?;
    client.ack(&qos1)?;
    client.ack(&qos2)?;
    wait_v5_completion(&mut connection, &expected)?;
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

fn wait_v5_manual_publishes(
    connection: &mut v5::Connection,
    expected_dup: bool,
) -> Result<(v5::mqttbytes::v5::Publish, v5::mqttbytes::v5::Publish), Box<dyn Error>> {
    use v5::mqttbytes::QoS as V5QoS;

    let mut qos1 = None;
    let mut qos2 = None;
    while qos1.is_none() || qos2.is_none() {
        match next_v5(connection)? {
            v5::Event::Incoming(v5::Incoming::Publish(publish)) => {
                if publish.retain || publish.dup != expected_dup || publish.pkid == 0 {
                    return Err(format!("rumqttc v5 unexpected crash PUBLISH: {publish:?}").into());
                }
                if publish.topic.as_ref() == V5_QOS1_TOPIC.as_bytes()
                    && publish.payload.as_ref() == V5_QOS1_PAYLOAD
                    && publish.qos == V5QoS::AtLeastOnce
                    && qos1.is_none()
                {
                    qos1 = Some(publish);
                } else if publish.topic.as_ref() == V5_QOS2_TOPIC.as_bytes()
                    && publish.payload.as_ref() == V5_QOS2_PAYLOAD
                    && publish.qos == V5QoS::ExactlyOnce
                    && qos2.is_none()
                {
                    qos2 = Some(publish);
                } else {
                    return Err(format!(
                        "rumqttc v5 unexpected or duplicate crash PUBLISH: {publish:?}"
                    )
                    .into());
                }
            }
            v5::Event::Outgoing(rumqttc::Outgoing::PubAck(_))
            | v5::Event::Outgoing(rumqttc::Outgoing::PubRec(_)) => {
                return Err("rumqttc v5 sent acknowledgement with manual ACK enabled".into());
            }
            _ => {}
        }
    }
    Ok((qos1.unwrap(), qos2.unwrap()))
}

fn wait_v5_completion(
    connection: &mut v5::Connection,
    expected: &PacketIds,
) -> Result<(), Box<dyn Error>> {
    let mut puback = false;
    let mut pubrec = false;
    let mut pubrel = false;
    let mut pubcomp = false;
    while !puback || !pubrec || !pubrel || !pubcomp {
        match next_v5(connection)? {
            v5::Event::Outgoing(rumqttc::Outgoing::PubAck(packet_id)) => {
                require_once("v5 PUBACK", packet_id, expected.qos1, &mut puback)?;
            }
            v5::Event::Outgoing(rumqttc::Outgoing::PubRec(packet_id)) => {
                require_once("v5 PUBREC", packet_id, expected.qos2, &mut pubrec)?;
            }
            v5::Event::Incoming(v5::Incoming::PubRel(packet)) => {
                require_once("v5 PUBREL", packet.pkid, expected.qos2, &mut pubrel)?;
            }
            v5::Event::Outgoing(rumqttc::Outgoing::PubComp(packet_id)) => {
                require_once("v5 PUBCOMP", packet_id, expected.qos2, &mut pubcomp)?;
            }
            v5::Event::Incoming(v5::Incoming::Publish(_)) => {
                return Err("rumqttc v5 duplicate PUBLISH during acknowledgement".into());
            }
            _ => {}
        }
    }
    Ok(())
}

fn wait_v5_pubcomp(connection: &mut v5::Connection) -> Result<(), Box<dyn Error>> {
    loop {
        match next_v5(connection)? {
            v5::Event::Incoming(v5::Incoming::PubComp(_)) => return Ok(()),
            v5::Event::Incoming(v5::Incoming::Publish(_)) => {
                return Err("rumqttc v5 publisher received unexpected PUBLISH".into());
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

fn require_packet_ids(
    protocol: &str,
    qos1: u16,
    qos2: u16,
    expected: &PacketIds,
) -> Result<(), Box<dyn Error>> {
    if qos1 != expected.qos1 || qos2 != expected.qos2 {
        return Err(format!(
            "rumqttc {protocol} restored Packet Identifiers changed: got={qos1}/{qos2} expected={}/{}",
            expected.qos1, expected.qos2
        )
        .into());
    }
    Ok(())
}

fn require_once(
    label: &str,
    packet_id: u16,
    expected_packet_id: u16,
    seen: &mut bool,
) -> Result<(), Box<dyn Error>> {
    if packet_id != expected_packet_id || *seen {
        return Err(format!(
            "rumqttc unexpected {label}: packet_id={packet_id} expected={expected_packet_id} duplicate={}",
            *seen
        )
        .into());
    }
    *seen = true;
    Ok(())
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
