/* Node-type: quic.
 *
 * Author: Steffen Vogel <post@steffenvogel.de>
 * Author: Salome Enahoro
 * SPDX-FileCopyrightText: 2014-2023 Institute for Automation of Complex Power Systems, RWTH Aachen University
 * SPDX-License-Identifier: Apache-2.0
 */

#include <mutex>
#include <jansson.h>
#include <msquic.h>
#include <villas/jansson.hpp>
#include <villas/nodes/quic.hpp>
#include <villas/exceptions.hpp>
#include <villas/sample.hpp>
#include <villas/super_node.hpp>
#include <villas/timing.hpp>
#include <villas/utils.hpp>

namespace {
constexpr size_t MAX_STREAM_MESSAGE_SIZE = 1024 * 1024; // 1 MiB
}

using namespace villas;
using namespace villas::utils;
using namespace villas::node;

QuicNode::QuicNode(const uuid_t &id, const std::string &name)
    : Node(id, name),
      host(""),
      port(4433),
      mode("client"),
      transport("datagram"),
      certificateFile(""),
      privateKeyFile(""),
      caCertificateFile(""),
      datagramSendEnabled(false),
      maxDatagramSendLength(0),
      connectionShutdownComplete(true),
      api(nullptr),
      registration(nullptr),
      configuration(nullptr),
      connection(nullptr),
      stream(nullptr),
      listener(nullptr)
{
}
QuicNode::~QuicNode() {
  int ret = pool_destroy(&pool);
  if (ret)
    logger->error("Failed to destroy pool");

  ret = queue_signalled_destroy(&queue);
  if (ret)
    logger->error("Failed to destroy queue");
}

int QuicNode::parse(json_t *json) {
  int ret = Node::parse(json);
  if (ret)
    return ret;

  const char *host_str = nullptr;
  const char *mode_str = nullptr;
  const char *transport_str = nullptr;
  const char *cert_str = nullptr;
  const char *key_str = nullptr;
  const char *ca_str = nullptr;
  int port_value = 4433;
  json_t *json_format = nullptr;

  janssonUnpack(json,
              "{ s?: s, s?: s, s?: s, s?: i, s?: s, s?: s, s?: s, s?: o }",
              "host", &host_str,
              "mode", &mode_str,
              "transport_mode", &transport_str,
              "port", &port_value,
              "certificate", &cert_str,
              "private_key", &key_str,
              "ca_certificate", &ca_str,
              "format", &json_format);

if (host_str)
  host = host_str;

if (mode_str)
  mode = mode_str;

if (transport_str)
  transport = transport_str;

if (cert_str)
  certificateFile = cert_str;

if (key_str)
  privateKeyFile = key_str;

if (ca_str)
  caCertificateFile = ca_str;

if (mode != "client" && mode != "server")
    throw ConfigError(json, "node-config-node-quic-mode",
                      "Mode must be either 'client' or 'server'");

if (transport != "datagram" && transport != "stream")
    throw ConfigError(json, "node-config-node-quic-transport",
                      "Transport must be either 'datagram' or 'stream'");

if (port_value < 1 || port_value > 65535)
    throw ConfigError(json, "node-config-node-quic-port",
                      "Port must be between 1 and 65535");

port = static_cast<uint16_t>(port_value);

auto *fmt= json_format ? FormatFactory::make(json_format)
                          : FormatFactory::make("villas.binary");

  formatter = Format::Ptr(fmt);

  if (!formatter)
    throw ConfigError(json_format, "node-config-node-quic-format",
                      "Invalid format configuration");


return 0;
}

int QuicNode::prepare()
{
  if (mode == "server") {
    if (certificateFile.empty() || privateKeyFile.empty()) {
        logger->error("Server mode requires 'certificate' and 'private_key'");
        return -1;
    }
  }
  else {
    if (caCertificateFile.empty()) {
        logger->error("Client mode requires 'ca_certificate' for certificate validation");
        return -1;
    }
  }

  QUIC_STATUS status = MsQuicOpen2(&api);

  if (QUIC_FAILED(status)) {
    logger->error("Failed to open MsQuic:{}", status);
    return -1;
  };

  QUIC_REGISTRATION_CONFIG registrationconfig = {
    "villas_quic",
    QUIC_EXECUTION_PROFILE_LOW_LATENCY
  };

  status = api->RegistrationOpen(&registrationconfig, &registration);

  if (QUIC_FAILED(status)) {
    logger->error("Failed to open MsQuic registration: {}", status);
    MsQuicClose(api);
    api = nullptr;
    return -1;
  }

  QUIC_SETTINGS settings = {};

  if (transport == "datagram") {
    settings.IsSet.DatagramReceiveEnabled = TRUE;
    settings.DatagramReceiveEnabled = TRUE;
  } else {
    settings.IsSet.DatagramReceiveEnabled = TRUE;
    settings.DatagramReceiveEnabled = FALSE;
  }
    const uint8_t alpnData[] = "villas-quic";

  if (transport == "stream") {
    settings.IsSet.PeerBidiStreamCount = TRUE;
    settings.PeerBidiStreamCount = 1;
  }
  QUIC_BUFFER alpn = {
      sizeof(alpnData) - 1,
      const_cast<uint8_t *>(alpnData)
  };
  status = api->ConfigurationOpen(
    registration,
    &alpn,
    1,
    &settings,
    sizeof(settings),
    nullptr,
    &configuration
  );

  if (QUIC_FAILED(status)) {
    logger->error("Failed to open MsQuic configuration: {}", status);
    api->RegistrationClose(registration);
    registration = nullptr;
    MsQuicClose(api);
    api = nullptr;
    return -1;
  }
  QUIC_CERTIFICATE_FILE certFileConfig = {};
  QUIC_CREDENTIAL_CONFIG credentialConfig = {};

  if (mode == "server") {
    certFileConfig.CertificateFile = certificateFile.c_str();
    certFileConfig.PrivateKeyFile = privateKeyFile.c_str();

    credentialConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    credentialConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;
    credentialConfig.CertificateFile = &certFileConfig;
  }
  else {
    credentialConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
    credentialConfig.Flags =
        QUIC_CREDENTIAL_FLAG_CLIENT |
        QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE;

    credentialConfig.CaCertificateFile = caCertificateFile.c_str();
  }

  status = api->ConfigurationLoadCredential(configuration, &credentialConfig);

  if (QUIC_FAILED(status)) {
    logger->error("Failed to load QUIC credentials: {}", status);
    api->ConfigurationClose(configuration);
    configuration = nullptr;
    api->RegistrationClose(registration);
    registration = nullptr;
    MsQuicClose(api);
    api = nullptr;
    return -1;
  }

  if (QUIC_FAILED(status)) {
    logger->error("Failed to load MsQuic credentials: {}", status);

    api->ConfigurationClose(configuration);
    configuration = nullptr;

    api->RegistrationClose(registration);
    registration = nullptr;

    MsQuicClose(api);
    api = nullptr;

    return -1;
  }

  int ret = Node::prepare();
  if (ret)
    return ret;

  formatter->start(getInputSignals(false), ~(int)SampleFlags::HAS_OFFSET);

  ret = pool_init(&pool, 1024,
                  SAMPLE_LENGTH(getInputSignals(false)->size()));
  if (ret) {
    logger->error("Failed to create pool");
    return ret;
  }

  ret = queue_signalled_init(&queue, 1024);
  if (ret) {
    logger->error("Failed to create queue");
    return ret;
  }

  if (mode == "server") {
    status = api->ListenerOpen(
        registration,
        listenerCallback,
        this,
        &listener
    );

    if (QUIC_FAILED(status)) {
      logger->error("Failed to open QUIC listener: {}", status);
      return -1;
    }
  }

  return 0;
}

QUIC_STATUS QUIC_API QuicNode::listenerCallback(
    HQUIC listener,
    void *context,
    QUIC_LISTENER_EVENT *event
)
{
    auto *node = static_cast<QuicNode *>(context);

    switch (event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION: {
        HQUIC connection = event->NEW_CONNECTION.Connection;
        {
          std::lock_guard<std::mutex> lock(node->connectionMutex);

          if (node->connection != nullptr) {
                node->logger->warn(
                    "Rejecting incoming QUIC connection: "
                    "another connection is already active"
                );

                return QUIC_STATUS_CONNECTION_REFUSED;
          }

          node->connection = connection;
          node->connectionShutdownComplete = false;
        }

        node->api->SetCallbackHandler(
    connection,
    (void *)connectionCallback,
    node
        );

        QUIC_STATUS status = node->api->ConnectionSetConfiguration(
            connection,
            node->configuration
        );

        if (QUIC_FAILED(status)) {
            node->logger->error(
                "Failed to configure incoming QUIC connection: {}",
                status
            );
        }

        return status;
    }

    default:
        return QUIC_STATUS_SUCCESS;
    }
}


QUIC_STATUS QUIC_API QuicNode::connectionCallback(
    HQUIC connection,
    void *context,
    QUIC_CONNECTION_EVENT *event
)
{
    auto *node = static_cast<QuicNode *>(context);

    switch (event->Type) {

    case QUIC_CONNECTION_EVENT_CONNECTED:
        node->logger->info("QUIC connection established successfully");
        break;

    case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED:
        node->datagramSendEnabled =
            event->DATAGRAM_STATE_CHANGED.SendEnabled;

        node->maxDatagramSendLength =
            event->DATAGRAM_STATE_CHANGED.MaxSendLength;

        node->logger->info(
            "QUIC DATAGRAM sending {} (maximum payload: {} bytes)",
            node->datagramSendEnabled.load() ? "enabled" : "disabled",
            node->maxDatagramSendLength.load()
        );
        break;

    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED: {
        const QUIC_BUFFER *buffer = event->DATAGRAM_RECEIVED.Buffer;

        std::vector<Sample *> smps(node->in.vectorize);

        int allocated = sample_alloc_many(
            &node->pool, smps.data(), smps.size()
        );

        if (allocated <= 0) {
            node->logger->error(
                "Failed to allocate samples for QUIC DATAGRAM"
            );
            break;
        }

        int parsed = node->formatter->sscan(
            (const char *)buffer->Buffer,
            buffer->Length,
            nullptr,
            smps.data(),
            allocated
        );

        if (parsed < 0) {
            node->logger->error(
                "Failed to parse received QUIC DATAGRAM"
            );
            sample_decref_many(smps.data(), allocated);
            break;
        }

        if (parsed < allocated)
            sample_decref_many(
                smps.data() + parsed, allocated - parsed
            );

        if (parsed == 0)
            break;

        int pushed = queue_signalled_push_many(
            &node->queue,
            (void **)smps.data(),
            parsed
        );

        if (pushed < 0) {
            node->logger->error(
                "Failed to enqueue received QUIC samples"
            );
            sample_decref_many(smps.data(), parsed);
            break;
        }

        if (pushed < parsed)
            sample_decref_many(
                smps.data() + pushed, parsed - pushed
            );

        node->logger->trace(
            "Received {} samples via QUIC DATAGRAM", pushed
        );
        break;
    }

    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED: {
        auto *sendContext = static_cast<DatagramSendContext *>(
            event->DATAGRAM_SEND_STATE_CHANGED.ClientContext
        );

        if (sendContext != nullptr &&
            QUIC_DATAGRAM_SEND_STATE_IS_FINAL(
                event->DATAGRAM_SEND_STATE_CHANGED.State
            )) {
            delete sendContext;
        }

        break;
    }

    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        node->logger->error(
            "QUIC transport shutdown: {}",
            event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status
        );
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        node->logger->info("QUIC shutdown initiated by peer");
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        node->logger->info("QUIC connection shutdown complete");
        node ->api->ConnectionClose(connection);
        {
            std::lock_guard<std::mutex> lock(node->connectionMutex);
            if (node->connection == connection)
              node->connection = nullptr;

            node->connectionShutdownComplete = true;
        }

        node->shutdownCondition.notify_all();
        break;

    default:
        break;
    }

    return QUIC_STATUS_SUCCESS;
}

int QuicNode::start()
{
    int ret = Node::start();
    if (ret)
        return ret;

    if (mode == "server") {
        const uint8_t alpnData[] = "villas-quic";

        QUIC_BUFFER alpn = {
            sizeof(alpnData) - 1,
            const_cast<uint8_t *>(alpnData)
        };

        QUIC_ADDR address = {};
        QuicAddrSetFamily(&address, QUIC_ADDRESS_FAMILY_UNSPEC);
        QuicAddrSetPort(&address, port);

        QUIC_STATUS status = api->ListenerStart(
            listener,
            &alpn,
            1,
            &address
        );

        if (QUIC_FAILED(status)) {
            logger->error("Failed to start QUIC listener: {}", status);
          {
            std::lock_guard<std::mutex> lock(connectionMutex);
            api->ConnectionClose(newconnection);
            if (connection == newconnection)
              connection = nullptr;

            connectionShutdownComplete = true;
    }
            return -1;
        }
    }
    else {
      HQUIC newconnection = nullptr;
      QUIC_STATUS status = api->ConnectionOpen(
        registration,
        connectionCallback,
        this,
        &newconnection
      );

      if (QUIC_FAILED(status)) {
        logger->error("Failed to open QUIC connection: {}", status);
        return -1;
      }

      {
        std::lock_guard<std::mutex> lock(connectionMutex);
        connection = newconnection;
        connectionShutdownComplete = false;
      }

      status = api->ConnectionStart(
        newconnection,
        configuration,
        QUIC_ADDRESS_FAMILY_UNSPEC,
        host.c_str(),
        port
      );

      if (QUIC_FAILED(status)) {
        logger->error("Failed to start QUIC connection: {}", status);
        std::lock_guard<std::mutex> lock(connectionMutex);
        api->ConnectionClose(newconnection);
        connection = nullptr;
        connectionShutdownComplete = true;
        return -1;
      }
  }
  return 0;
}

int QuicNode::stop()
{
    if (listener != nullptr) {
        api->ListenerStop(listener);
        api->ListenerClose(listener);
        listener = nullptr;
    }
    HQUIC connectiontoshutdown = nullptr;
    {
        std::unique_lock<std::mutex> lock(connectionMutex);
        connectiontoshutdown = connection;

        if (connectiontoshutdown != nullptr) {
            api->ConnectionShutdown(
                connection,
                QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                0
            );
            std::unique_lock<std::mutex> lock(connectionMutex);

            shutdownCondition.wait(lock, [this] {
                return connectionShutdownComplete;
            });
        }
    }

    if (configuration != nullptr) {
        api->ConfigurationClose(configuration);
        configuration = nullptr;
    }

    if (registration != nullptr) {
        api->RegistrationClose(registration);
        registration = nullptr;
    }

    if (api != nullptr) {
        MsQuicClose(api);
        api = nullptr;
    }

    return Node::stop();
}

std::vector<int> QuicNode::getPollFDs()
{
    return {queue_signalled_fd(&queue)};
}
const std::string &QuicNode::getDetails()
{
    details = fmt::format(
        "host={}, port={}, mode={}, transport={}",
        host,
        port,
        mode,
        transport
    );

    return details;
}
int QuicNode::_read(struct Sample *smps[], unsigned cnt)
{
    std::vector<Sample *> smpt;
    smpt.resize(cnt);

    int pulled = queue_signalled_pull_many(
        &queue,
        (void **)smpt.data(),
        smpt.size()
    );

    sample_copy_many(smps, smpt.data(), pulled);
    sample_decref_many(smpt.data(), pulled);

    return pulled;
}

json_t *QuicNode::_readStatus() const
{
    return nullptr;
}
int QuicNode::_write(struct Sample *smps[], unsigned cnt)
{
  if (transport != "datagram") {
      logger->error("QUIC STREAM transmission is not implemented yet");
      return -1;
  }

  if (!datagramSendEnabled.load()) {
      logger->error("QUIC DATAGRAM sending is currently disabled");
      return -1;
  }

  uint16_t maxLength = maxDatagramSendLength.load();
  if (maxLength == 0) {
      logger->error("Invalid QUIC DATAGRAM maximum payload length");
      return -1;
  }

  HQUIC connectionhandle = nullptr;
  {
      std::lock_guard<std::mutex> lock(connectionMutex);
      connectionhandle = connection;
  }

  if (connectionhandle == nullptr) {
      logger->error("QUIC DATAGRAM sending requested while disconnected");
      return -1;
  }

  auto *sendContext = new DatagramSendContext{};
  sendContext->data.resize(maxLength);

  size_t written = 0;

  int ret = formatter->sprint(
      reinterpret_cast<char *>(sendContext->data.data()),
      sendContext->data.size(),
      &written,
      smps,
      cnt
  );

  if (ret < 0) {
      logger->error("Failed to format QUIC DATAGRAM payload");
      delete sendContext;
      return ret;
  }

  if (written > maxLength) {
      logger->error("Formatted payload exceeds QUIC DATAGRAM maximum length");
      delete sendContext;
      return -1;
  }

  sendContext->data.resize(written);

  sendContext->buffer.Length = static_cast<uint32_t>(written);
  sendContext->buffer.Buffer = sendContext->data.data();

  QUIC_STATUS status = api->DatagramSend(
      connection,
      &sendContext->buffer,
      1,
      QUIC_SEND_FLAG_NONE,
      sendContext
  );

  if (QUIC_FAILED(status)) {
      logger->error("Failed to send QUIC DATAGRAM: {}", status);
      delete sendContext;
      return -1;
  }

  logger->trace("Sent {} samples via QUIC DATAGRAM", ret);

  return ret;
}

int QuicNodeFactory::start(SuperNode *sn)
{
    return 0;
}

static QuicNodeFactory p;
