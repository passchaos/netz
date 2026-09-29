use std::error::Error;
use std::time::Duration;

use rumqttc::{Client, MqttOptions, QoS};

use super::{
    disconnect_v4, disconnect_v5, wait_v4_connack, wait_v4_puback, wait_v4_publish, wait_v4_suback,
    wait_v5_connack, wait_v5_puback, wait_v5_publish, wait_v5_suback,
};
use rumqttc::v5;

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

pub fn recover(port: u16) -> Result<(), Box<dyn Error>> {
    recover_v4(port)?;
    recover_v5(port)?;
    Ok(())
}

fn prepare_v4(port: u16) -> Result<(), Box<dyn Error>> {
    let mut options = MqttOptions::new(V4_CLIENT_ID, "127.0.0.1", port);
    options.set_keep_alive(Duration::from_secs(5));
    options.set_clean_session(false);
    let (client, mut connection) = Client::new(options, 16);
    wait_v4_connack(&mut connection, false)?;
    client.subscribe(V4_TOPIC, QoS::AtLeastOnce)?;
    wait_v4_suback(&mut connection, QoS::AtLeastOnce)?;
    disconnect_v4(&client, &mut connection)?;

    let mut publisher_options =
        MqttOptions::new("netz-rumqttc-v4-crash-publisher", "127.0.0.1", port);
    publisher_options.set_keep_alive(Duration::from_secs(5));
    publisher_options.set_clean_session(true);
    let (publisher, mut publisher_connection) = Client::new(publisher_options, 16);
    wait_v4_connack(&mut publisher_connection, false)?;
    publisher.publish(V4_TOPIC, QoS::AtLeastOnce, false, V4_PAYLOAD)?;
    wait_v4_puback(&mut publisher_connection)?;
    disconnect_v4(&publisher, &mut publisher_connection)?;
    Ok(())
}

fn recover_v4(port: u16) -> Result<(), Box<dyn Error>> {
    let mut options = MqttOptions::new(V4_CLIENT_ID, "127.0.0.1", port);
    options.set_keep_alive(Duration::from_secs(5));
    options.set_clean_session(false);
    let (client, mut connection) = Client::new(options, 16);
    wait_v4_connack(&mut connection, true)?;
    wait_v4_publish(
        &mut connection,
        V4_TOPIC,
        V4_PAYLOAD,
        QoS::AtLeastOnce,
        false,
        false,
    )?;
    client.publish(
        "rumqttc/v4/crash-barrier",
        QoS::AtLeastOnce,
        false,
        b"barrier".as_slice(),
    )?;
    wait_v4_puback(&mut connection)?;
    disconnect_v4(&client, &mut connection)?;
    Ok(())
}

fn prepare_v5(port: u16) -> Result<(), Box<dyn Error>> {
    use v5::mqttbytes::QoS as V5QoS;

    let mut options = v5::MqttOptions::new(V5_CLIENT_ID, "127.0.0.1", port);
    options.set_keep_alive(Duration::from_secs(5));
    options.set_clean_start(false);
    options.set_session_expiry_interval(Some(60));
    let (client, mut connection) = v5::Client::new(options, 16);
    wait_v5_connack(&mut connection, false)?;
    client.subscribe(V5_TOPIC, V5QoS::AtLeastOnce)?;
    wait_v5_suback(&mut connection, V5QoS::AtLeastOnce)?;
    disconnect_v5(&client, &mut connection)?;

    let mut publisher_options =
        v5::MqttOptions::new("netz-rumqttc-v5-crash-publisher", "127.0.0.1", port);
    publisher_options.set_keep_alive(Duration::from_secs(5));
    publisher_options.set_clean_start(true);
    let (publisher, mut publisher_connection) = v5::Client::new(publisher_options, 16);
    wait_v5_connack(&mut publisher_connection, false)?;
    publisher.publish(V5_TOPIC, V5QoS::AtLeastOnce, false, V5_PAYLOAD)?;
    wait_v5_puback(&mut publisher_connection)?;
    disconnect_v5(&publisher, &mut publisher_connection)?;
    Ok(())
}

fn recover_v5(port: u16) -> Result<(), Box<dyn Error>> {
    use v5::mqttbytes::QoS as V5QoS;

    let mut options = v5::MqttOptions::new(V5_CLIENT_ID, "127.0.0.1", port);
    options.set_keep_alive(Duration::from_secs(5));
    options.set_clean_start(false);
    options.set_session_expiry_interval(Some(60));
    let (client, mut connection) = v5::Client::new(options, 16);
    wait_v5_connack(&mut connection, true)?;
    wait_v5_publish(
        &mut connection,
        V5_TOPIC,
        V5_PAYLOAD,
        V5QoS::AtLeastOnce,
        false,
        false,
        false,
    )?;
    client.publish(
        "rumqttc/v5/crash-barrier",
        V5QoS::AtLeastOnce,
        false,
        b"barrier".as_slice(),
    )?;
    wait_v5_puback(&mut connection)?;
    disconnect_v5(&client, &mut connection)?;
    Ok(())
}
