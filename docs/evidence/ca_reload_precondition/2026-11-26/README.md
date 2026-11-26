# Client CA reload precondition observation

The native Linux and complete runs at 59ce674b fail while reading the retained
MQTT PINGRESP before SIGHUP. MQTT, capath and WSS identities have connected;
new untrusted identities have been rejected and an anonymous OpenSSL client
has completed CONNECT/PING. The connection's last non-consuming observations
report idle TCP and no buffered TLS plaintext, which does not identify the
service-side error.

The configured runner now forwards an optional listener error observer through
both ordinary and managed continuous service. The CA interop case enables
`NETZ_MQTT_CONFIG_TRACE_ERRORS=1`; at most 32 events identify listener index,
accept/connection stage and the original error. Default broker runs leave it
disabled. Existing pins, budgets and liveness traffic are unchanged.

The local actual-socket precondition passes in ordinary service and with the
public persistence configuration activating the management loop. The trace
mode observes three expected CertificateUntrusted accept events; default mode
emits none. Both retain MQTT/capath/WSS liveness. These are macOS precondition
checks and do not certify Linux SIGHUP/reload behavior. [Validation](validation.json)
keeps the remaining native Linux failure separate from the diagnostic result.
