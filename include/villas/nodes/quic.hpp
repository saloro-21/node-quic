/* Node-type quic.
 *
 * Author: Steffen Vogel <post@steffenvogel.de>
 * Author: Salome Enahoro
 * SPDX-FileCopyrightText: 2014-2023 Institute for Automation of Complex Power Systems, RWTH Aachen University
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <msquic.h>
#include <cstdint>
#include <condition_variable>
#include <mutex>
#include <villas/format.hpp>
#include <villas/node.hpp>
#include <villas/node/config.hpp>
#include <villas/queue_signalled.h>
#include <villas/timing.hpp>

namespace villas {
namespace node {

// Forward declarations
struct Sample;

class QuicNode : public Node {

protected:
  const QUIC_API_TABLE *api = nullptr;

  HQUIC registration = nullptr;
  HQUIC configuration = nullptr;
  HQUIC connection = nullptr;
  HQUIC stream = nullptr;
  HQUIC listener = nullptr;

  std::string host;
  uint16_t port = 0;
  std::string mode = "client";
  std::string transport = "datagram";
  std::mutex shutdownMutex;
  std::condition_variable shutdownCondition;
  bool connectionShutdownComplete = false;

  Format::Ptr formatter;
  struct CQueueSignalled queue;
  struct Pool pool;

  int _read(struct Sample *smps[], unsigned cnt) override;
  int _write(struct Sample *smps[], unsigned cnt) override;

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

  Node *make(const uuid_t &id = {}, const std::string &nme = "") override {
    auto *n = new QuicNode(id, nme);

    init(n);

    return n;
  }

  int getFlags() const override {
    return (int)NodeFactory::Flags::SUPPORTS_READ |
           (int)NodeFactory::Flags::SUPPORTS_WRITE |
           (int)NodeFactory::Flags::SUPPORTS_POLL;
  }

  std::string getName() const override { return "quic"; }

  std::string getDescription() const override {
    return "QUIC Communication";
  }

  int start(SuperNode *sn) override;
};

} // namespace node
} // namespace villas
