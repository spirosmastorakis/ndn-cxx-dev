/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2013-2015 Regents of the University of California.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 */

#include "face.hpp"
#include "detail/face-impl.hpp"

#include "encoding/tlv.hpp"
#include "security/key-chain.hpp"
#include "security/signing-helpers.hpp"
#include "util/time.hpp"
#include "util/random.hpp"
#include "util/face-uri.hpp"

#include "ns3/log.h"
#include "ns3/packet.h"
#include "ns3/node.h"
#include "ns3/assert.h"
#include "ns3/simulator.h"

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/point-to-point-layout-module.h"
#include "ns3/ndnSIM-module.h"

NS_LOG_COMPONENT_DEFINE("ndn.cxx.Face");

namespace ndn {

Face::Face()
  : ::nfd::Face(::nfd::FaceUri("ndnFace://"), ::nfd::FaceUri("ndnFace://"))
  , m_internalIoService(new boost::asio::io_service())
  , m_ioService(*m_internalIoService)
  // , m_internalKeyChain(new KeyChain())
  , m_impl(new Impl(*this))
{
  construct(*m_internalKeyChain);

  ns3::Ptr<ns3::Node> node = ns3::NodeList::GetNode(ns3::Simulator::GetContext());
  NS_LOG_INFO(node << " Creating ndn::Face");

  // NS_ASSERT_MSG(node->GetObject<ns3::ndn::L3Protocol>() != 0,
  //               " NDN stack should be installed on the node " << node);

  // node->GetObject<ns3::ndn::L3Protocol>()->addFace(make_shared<::nfd::Face>(*this));
}

Face::Face(boost::asio::io_service& ioService)
  : ::nfd::Face(::nfd::FaceUri("ndnFace://"), ::nfd::FaceUri("ndnFace://"))
  , m_ioService(ioService)
    //, m_internalKeyChain(new KeyChain())
  , m_impl(new Impl(*this))
{
  //construct(*m_internalKeyChain);

  // ns3::Ptr<ns3::Node> node = ns3::NodeList::GetNode(ns3::Simulator::GetContext());
  // NS_LOG_INFO(node << "Creating ndn::Face");

  // NS_ASSERT_MSG(node->GetObject<ns3::ndn::L3Protocol>() != 0,
  //                "NDN stack should be installed on the node " << node);

  //node->GetObject<ns3::ndn::L3Protocol>()->addFace((*this).shared_from_this());
}

Face::Face(const std::string& host, const std::string& port/* = "6363"*/)
  : ::nfd::Face(::nfd::FaceUri("ndnFace://"), ::nfd::FaceUri("ndnFace://"))
  , m_internalIoService(new boost::asio::io_service())
  , m_ioService(*m_internalIoService)
    //, m_internalKeyChain(new KeyChain())
  , m_impl(new Impl(*this))
{
  //construct(make_shared<TcpTransport>(host, port), *m_internalKeyChain);

  // ns3::Ptr<ns3::Node> node = ns3::NodeList::GetNode(ns3::Simulator::GetContext());
  // NS_LOG_INFO(node << "Creating ndn::Face");

  // NS_ASSERT_MSG(node->GetObject<ns3::ndn::L3Protocol>() != 0,
  //                "NDN stack should be installed on the node " << node);

  //node->GetObject<ns3::ndn::L3Protocol>()->addFace((*this).shared_from_this());
}

Face::Face(const shared_ptr<Transport>& transport)
  : ::nfd::Face(::nfd::FaceUri("ndnFace://"), ::nfd::FaceUri("ndnFace://"))
  , m_internalIoService(new boost::asio::io_service())
  , m_ioService(*m_internalIoService)
    //, m_internalKeyChain(new KeyChain())
  , m_impl(new Impl(*this))
{
  //construct(transport, *m_internalKeyChain);

  // ns3::Ptr<ns3::Node> node = ns3::NodeList::GetNode(ns3::Simulator::GetContext());
  // NS_LOG_INFO(node << "Creating ndn::Face");

  // NS_ASSERT_MSG(node->GetObject<ns3::ndn::L3Protocol>() != 0,
  //                "NDN stack should be installed on the node " << node);

  //node->GetObject<ns3::ndn::L3Protocol>()->addFace((*this).shared_from_this());
}

Face::Face(const shared_ptr<Transport>& transport,
           boost::asio::io_service& ioService)
  : ::nfd::Face(::nfd::FaceUri("ndnFace://"), ::nfd::FaceUri("ndnFace://"))
  , m_ioService(ioService)
    //, m_internalKeyChain(new KeyChain())
  , m_impl(new Impl(*this))
{
  //construct(transport, *m_internalKeyChain);

  // ns3::Ptr<ns3::Node> node = ns3::NodeList::GetNode(ns3::Simulator::GetContext());
  // NS_LOG_INFO(node << "Creating ndn::Face");

  // NS_ASSERT_MSG(node->GetObject<ns3::ndn::L3Protocol>() != 0,
  //                "NDN stack should be installed on the node " << node);

  //node->GetObject<ns3::ndn::L3Protocol>()->addFace((*this).shared_from_this());
}

Face::Face(shared_ptr<Transport> transport,
           boost::asio::io_service& ioService,
           KeyChain& keyChain)
  : ::nfd::Face(::nfd::FaceUri("ndnFace://"), ::nfd::FaceUri("ndnFace://"))
  , m_ioService(ioService)
    //, m_internalKeyChain(nullptr)
  , m_impl(new Impl(*this))
{
  //construct(transport, keyChain);

  // ns3::Ptr<ns3::Node> node = ns3::NodeList::GetNode(ns3::Simulator::GetContext());
  // NS_LOG_INFO(node << "Creating ndn::Face");

  // NS_ASSERT_MSG(node->GetObject<ns3::ndn::L3Protocol>() != 0,
  //                "NDN stack should be installed on the node " << node);

  // node->GetObject<ns3::ndn::L3Protocol>()->addFace((*this).shared_from_this());
}

void
Face::construct(KeyChain& keyChain)
{
  // transport=unix:///var/run/nfd.sock
  // transport=tcp://localhost:6363

  ConfigFile config;
  const auto& transportType = config.getParsedConfiguration()
                                .get_optional<std::string>("transport");
  if (!transportType) {
    // transport not specified, use default Unix transport.
    construct(UnixTransport::create(config), keyChain);
    return;
  }

  unique_ptr<util::FaceUri> uri;
  try {
    uri.reset(new util::FaceUri(*transportType));
  }
  catch (const util::FaceUri::Error& error) {
    throw ConfigFile::Error(error.what());
  }

  const std::string protocol = uri->getScheme();

  if (protocol == "unix") {
    construct(UnixTransport::create(config), keyChain);
  }
  else if (protocol == "tcp" || protocol == "tcp4" || protocol == "tcp6") {
    construct(TcpTransport::create(config), keyChain);
  }
  else {
    throw ConfigFile::Error("Unsupported transport protocol \"" + protocol + "\"");
  }
}

void
Face::construct(shared_ptr<Transport> transport, KeyChain& keyChain)
{
  m_nfdController.reset(new nfd::Controller(*this, ns3::ndn::StackHelper::getKeyChain()));

  // m_transport = transport;

  // m_impl->ensureConnected(false);
}

Face::~Face() = default;

const PendingInterestId*
Face::expressInterest(const Interest& interest, const OnData& onData, const OnTimeout& onTimeout)
{
  NS_LOG_INFO (">> Interest: " << interest.getName());

  shared_ptr<Interest> interestToExpress = make_shared<Interest>(interest);

  // Use `interestToExpress` to avoid wire format creation for the original Interest
  if (interestToExpress->wireEncode().size() > MAX_NDN_PACKET_SIZE)
    throw Error("Interest size exceeds maximum limit");

  // If the same ioService thread, dispatch directly calls the method
  //m_ioService.dispatch([=] { m_impl->asyncExpressInterest(interestToExpress, onData, onTimeout); });
  // m_impl->m_scheduler.scheduleEvent(time::seconds(0),
  //                                   [&interestToExpress, &onData, &onTimeout, this] {
  //                                     m_impl->asyncExpressInterest(interestToExpress, onData, onTimeout);
  //                                   });
  m_impl->asyncExpressInterest(interestToExpress, onData, onTimeout);

  return reinterpret_cast<const PendingInterestId*>(interestToExpress.get());
}

const PendingInterestId*
Face::expressInterest(const Name& name,
                      const Interest& tmpl,
                      const OnData& onData, const OnTimeout& onTimeout/* = OnTimeout()*/)
{
  return expressInterest(Interest(tmpl)
                         .setName(name)
                         .setNonce(0),
                         onData, onTimeout);
}

void
Face::put(const Data& data)
{
   NS_LOG_INFO (">> Data: " << data.getName());

  // Use original `data`, since wire format should already exist for the original Data
  if (data.wireEncode().size() > MAX_NDN_PACKET_SIZE)
    throw Error("Data size exceeds maximum limit");

  shared_ptr<const Data> dataPtr;
  try {
    dataPtr = data.shared_from_this();
  }
  catch (const bad_weak_ptr& e) {
    NS_LOG_INFO("Face::put WARNING: the supplied Data should be created using make_shared<Data>()");
    dataPtr = make_shared<Data>(data);
  }

  // If the same ioService thread, dispatch directly calls the method
  // m_ioService.dispatch([=] { m_impl->asyncPutData(dataPtr); });
  m_impl->asyncPutData(dataPtr);
}

void
Face::removePendingInterest(const PendingInterestId* pendingInterestId)
{
  // m_ioService.post([=] { m_impl->asyncRemovePendingInterest(pendingInterestId); });
  m_impl->asyncRemovePendingInterest(pendingInterestId);
}

size_t
Face::getNPendingInterests() const
{
  return m_impl->m_pendingInterestTable.size();
}

const RegisteredPrefixId*
Face::setInterestFilter(const InterestFilter& interestFilter,
                  const OnInterest& onInterest,
                  const RegisterPrefixFailureCallback& onFailure,
                  const security::SigningInfo& signingInfo,
                  uint64_t flags)
{
    return setInterestFilter(interestFilter,
                             onInterest,
                             RegisterPrefixSuccessCallback(),
                             onFailure,
                             signingInfo,
                             flags);
}

const RegisteredPrefixId*
Face::setInterestFilter(const InterestFilter& interestFilter,
                  const OnInterest& onInterest,
                  const RegisterPrefixSuccessCallback& onSuccess,
                  const RegisterPrefixFailureCallback& onFailure,
                  const security::SigningInfo& signingInfo,
                  uint64_t flags)
{
    shared_ptr<InterestFilterRecord> filter =
      make_shared<InterestFilterRecord>(interestFilter, onInterest);

    nfd::CommandOptions options;
    options.setSigningInfo(signingInfo);

    return m_impl->registerPrefix(interestFilter.getPrefix(), filter,
                                  onSuccess, onFailure,
                                  flags, options);
}

const InterestFilterId*
Face::setInterestFilter(const InterestFilter& interestFilter,
                        const OnInterest& onInterest)
{
  NS_LOG_INFO("Set Interest Filter << " << interestFilter);

  shared_ptr<InterestFilterRecord> filter =
    make_shared<InterestFilterRecord>(interestFilter, onInterest);

  // getIoService().post([=] { m_impl->asyncSetInterestFilter(filter); });
  m_impl->asyncSetInterestFilter(filter);

  return reinterpret_cast<const InterestFilterId*>(filter.get());
}

#ifdef NDN_FACE_KEEP_DEPRECATED_REGISTRATION_SIGNING

const RegisteredPrefixId*
Face::setInterestFilter(const InterestFilter& interestFilter,
                        const OnInterest& onInterest,
                        const RegisterPrefixSuccessCallback& onSuccess,
                        const RegisterPrefixFailureCallback& onFailure,
                        const IdentityCertificate& certificate,
                        uint64_t flags)
{
  security::SigningInfo signingInfo;
  if (!certificate.getName().empty()) {
    signingInfo = signingByCertificate(certificate.getName());
  }
  return setInterestFilter(interestFilter, onInterest,
                           onSuccess, onFailure,
                           signingInfo, flags);
}

const RegisteredPrefixId*
Face::setInterestFilter(const InterestFilter& interestFilter,
                        const OnInterest& onInterest,
                        const RegisterPrefixFailureCallback& onFailure,
                        const IdentityCertificate& certificate,
                        uint64_t flags)
{
  security::SigningInfo signingInfo;
  if (!certificate.getName().empty()) {
    signingInfo = signingByCertificate(certificate.getName());
  }
  return setInterestFilter(interestFilter, onInterest,
                             onFailure, signingInfo, flags);
}

const RegisteredPrefixId*
Face::setInterestFilter(const InterestFilter& interestFilter,
                        const OnInterest& onInterest,
                        const RegisterPrefixSuccessCallback& onSuccess,
                        const RegisterPrefixFailureCallback& onFailure,
                        const Name& identity,
                        uint64_t flags)
{
  security::SigningInfo signingInfo = signingByIdentity(identity);

  return setInterestFilter(interestFilter, onInterest,
                           onSuccess, onFailure,
                           signingInfo, flags);
}

const RegisteredPrefixId*
Face::setInterestFilter(const InterestFilter& interestFilter,
                        const OnInterest& onInterest,
                        const RegisterPrefixFailureCallback& onFailure,
                        const Name& identity,
                        uint64_t flags)
{
  security::SigningInfo signingInfo = signingByIdentity(identity);

  return setInterestFilter(interestFilter, onInterest,
                           onFailure, signingInfo, flags);
}

#endif // NDN_FACE_KEEP_DEPRECATED_REGISTRATION_SIGNING

const RegisteredPrefixId*
Face::registerPrefix(const Name& prefix,
               const RegisterPrefixSuccessCallback& onSuccess,
               const RegisterPrefixFailureCallback& onFailure,
               const security::SigningInfo& signingInfo,
               uint64_t flags)
{

    nfd::CommandOptions options;
    options.setSigningInfo(signingInfo);

    return m_impl->registerPrefix(prefix, shared_ptr<InterestFilterRecord>(),
                                  onSuccess, onFailure,
                                  flags, options);
}

#ifdef NDN_FACE_KEEP_DEPRECATED_REGISTRATION_SIGNING
const RegisteredPrefixId*
Face::registerPrefix(const Name& prefix,
                     const RegisterPrefixSuccessCallback& onSuccess,
                     const RegisterPrefixFailureCallback& onFailure,
                     const IdentityCertificate& certificate,
                     uint64_t flags)
{
  security::SigningInfo signingInfo;
  if (!certificate.getName().empty()) {
    signingInfo = signingByCertificate(certificate.getName());
  }
  return registerPrefix(prefix, onSuccess,
                        onFailure, signingInfo, flags);
}

const RegisteredPrefixId*
Face::registerPrefix(const Name& prefix,
                     const RegisterPrefixSuccessCallback& onSuccess,
                     const RegisterPrefixFailureCallback& onFailure,
                     const Name& identity,
                     uint64_t flags)
{
  security::SigningInfo signingInfo = signingByIdentity(identity);
  return registerPrefix(prefix, onSuccess,
                        onFailure, signingInfo, flags);
}
#endif // NDN_FACE_KEEP_DEPRECATED_REGISTRATION_SIGNING

void
Face::unsetInterestFilter(const RegisteredPrefixId* registeredPrefixId)
{
  // m_ioService.post([=] { m_impl->asyncUnregisterPrefix(registeredPrefixId,
  //                                                      UnregisterPrefixSuccessCallback(),
  //                                                      UnregisterPrefixFailureCallback()); });
  m_impl->asyncUnregisterPrefix(registeredPrefixId,
                                UnregisterPrefixSuccessCallback(),
                                UnregisterPrefixFailureCallback());
}

void
Face::unsetInterestFilter(const InterestFilterId* interestFilterId)
{
  // m_ioService.post([=] { m_impl->asyncUnsetInterestFilter(interestFilterId); });
  m_impl->asyncUnsetInterestFilter(interestFilterId);
}

void
Face::unregisterPrefix(const RegisteredPrefixId* registeredPrefixId,
                       const UnregisterPrefixSuccessCallback& onSuccess,
                       const UnregisterPrefixFailureCallback& onFailure)
{
  // m_ioService.post([=] { m_impl->asyncUnregisterPrefix(registeredPrefixId,onSuccess, onFailure); });
  m_impl->asyncUnregisterPrefix(registeredPrefixId,onSuccess, onFailure);
}

void
Face::processEvents(const time::milliseconds& timeout/* = time::milliseconds::zero()*/,
                    bool keepThread/* = false*/)
{
  if (m_ioService.stopped()) {
    m_ioService.reset(); // ensure that run()/poll() will do some work
  }

  try {
    if (timeout < time::milliseconds::zero()) {
        // do not block if timeout is negative, but process pending events
        m_ioService.poll();
        return;
      }

    if (timeout > time::milliseconds::zero()) {
      boost::asio::io_service& ioService = m_ioService;
      unique_ptr<boost::asio::io_service::work>& work = m_impl->m_ioServiceWork;
      m_impl->m_processEventsTimeoutEvent =
        m_impl->m_scheduler.scheduleEvent(timeout, [&ioService, &work] {
            ioService.stop();
            work.reset();
          });
    }

    if (keepThread) {
      // work will ensure that m_ioService is running until work object exists
      m_impl->m_ioServiceWork.reset(new boost::asio::io_service::work(m_ioService));
    }

    m_ioService.run();
  }
  catch (...) {
    m_impl->m_ioServiceWork.reset();
    m_impl->m_pendingInterestTable.clear();
    m_impl->m_registeredPrefixTable.clear();
    throw;
  }
}

void
Face::shutdown()
{
  // m_ioService.post([this] { this->asyncShutdown(); });
  this->asyncShutdown();
}

void
Face::asyncShutdown()
{
  m_impl->m_pendingInterestTable.clear();
  m_impl->m_registeredPrefixTable.clear();

  // if (m_transport->isConnected())
  //   m_transport->close();

  this->close();

  m_impl->m_ioServiceWork.reset();
}

void
Face::onReceiveElement(const Block& blockFromDaemon)
{
  const Block& block = nfd::LocalControlHeader::getPayload(blockFromDaemon);

  if (block.type() == tlv::Interest)
    {
      shared_ptr<Interest> interest = make_shared<Interest>(block);
      if (&block != &blockFromDaemon)
        interest->getLocalControlHeader().wireDecode(blockFromDaemon);

      m_impl->processInterestFilters(*interest);
    }
  else if (block.type() == tlv::Data)
    {
      shared_ptr<Data> data = make_shared<Data>(block);
      if (&block != &blockFromDaemon)
        data->getLocalControlHeader().wireDecode(blockFromDaemon);

      m_impl->satisfyPendingInterests(*data);
    }
  // ignore any other type
}

void
Face::sendInterest(const Interest& interest)
{
  NS_LOG_FUNCTION(this << interest);
  this->emitSignal(onSendInterest, interest); // not sure if we need this
  this->onReceiveElement(interest.wireEncode());
}

void
Face::sendData(const Data& data)
{
  NS_LOG_FUNCTION(this << data);
  this->emitSignal(onSendData, data); // not sure if we need this
  this->onReceiveElement(data.wireEncode());
}

void
Face::onReceiveInterest(const Interest& interest)
{
  NS_LOG_FUNCTION(this << interest);
  this->emitSignal(onReceiveInterest, interest);
}

void
Face::onReceiveData(const Data& data)
{
  NS_LOG_FUNCTION(this << data);
  this->emitSignal(onReceiveData, data);
}

void
Face::close()
{
  this->fail("close");
}

} // namespace ndn
