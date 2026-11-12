/* Node-type quic.
 *
 * Author: Steffen Vogel <post@steffenvogel.de>
 * Author: Salome Enahoro
 * SPDX-FileCopyrightText: 2014-2023 Institute for Automation of Complex Power Systems, RWTH Aachen University
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <msquic.h>

#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <vector>
#include <atomic>
#include <string>

#include <villas/format.hpp>
#include <villas/node.hpp>
#include <villas/node/config.hpp>
#include <villas/pool.hpp>
#include <villas/queue_signalled.h>
#include <villas/timing.hpp>

namespace villas {
namespace node {

// Forward declarations
struct Sample;

class QuicNode : public Node {

protected:
  static constexpr char ALPN[] = "villas-quic";

  //Msquic handles
  const QUIC_API_TABLE *api = nullptr;

  HQUIC registration = nullptr;
  HQUIC configuration = nullptr;
  HQUIC listener = nullptr;
  HQUIC connection = nullptr;
  HQUIC stream = nullptr;


  //Connection configuration
  std::string host;
  uint16_t port = 4433;
  std::string mode = "client";
  std::string transport = "datagram";

  //Certificate paths
  std::string certificateFile;
  std::string privateKeyFile;
  std::string caCertificateFile;

  //Datagram state
  std::atomic<bool> datagramSendEnabled{false};
  std::atomic<uint16_t> maxDatagramSendLength{0};

  //Synchronization
  std::mutex connectionMutex;
  std::condition_variable shutdownCondition;
  bool connectionShutdownComplete = true;

  //Sample handling
  Format::Ptr formatter;
  struct CQueueSignalled queue = {};
  struct Pool pool = {};

  bool poolInitialized = false;
  bool queueInitialized = false;

  struct DatagramSendContext {
    std::vector<uint8_t> data;
    QUIC_BUFFER buffer;
  };

  struct StreamSendContext {
    std::vector<uint8_t> data;
    QUIC_BUFFER buffer;
  };
  std::vector<uint8_t> streamReceiveBuffer; //length prefixed messages
  std::mutex streamReceiveMutex;

  int _read(struct Sample *smps[], unsigned cnt) override;
  int _write(struct Sample *smps[], unsigned cnt) override;
  int _writeDatagram(struct Sample *smps[], unsigned cnt);
  int _writeStreams(struct Sample *smps[], unsigned cnt);

  json_t *_readStatus() const override;

  static QUIC_STATUS QUIC_API listenerCallback(
      HQUIC listener,
      void *context,
      QUIC_LISTENER_EVENT *event
  );

  static QUIC_STATUS QUIC_API connectionCallback(
    HQUIC connection,
    void *context,
    QUIC_CONNECTION_EVENT *event
);

  static QUIC_STATUS QUIC_API streamCallback(
    HQUIC stream,
    void *context,
    QUIC_STREAM_EVENT *event
);

public:
  QuicNode(const uuid_t &id = {}, const std::string &name = "");

  ~QuicNode() override;

  int prepare() override;

  int parse(json_t *json) override;

  int start() override;

  int stop() override;

  std::vector<int> getPollFDs() override;

  const std::string &getDetails() override;
};

class QuicNodeFactory : public NodeFactory {

public:
  using NodeFactory::NodeFactory;

  Node *make(const uuid_t &id = {}, const std::string &name = "") override {
    auto *n = new QuicNode(id, name);
    init(n);
    return n;
  }

  int getFlags() const override {
    return (int)NodeFactory::Flags::SUPPORTS_READ |
           (int)NodeFactory::Flags::SUPPORTS_WRITE |
           (int)NodeFactory::Flags::SUPPORTS_POLL;
  }

  std::string getName() const override {
    return "quic";
  }

  std::string getDescription() const override {
    return "QUIC Communication via msquic";
  }

  int start(SuperNode *sn) override;
};

}
}
