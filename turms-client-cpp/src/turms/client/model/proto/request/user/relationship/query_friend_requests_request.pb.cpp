// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: request/user/relationship/query_friend_requests_request.proto

#include "turms/client/model/proto/request/user/relationship/query_friend_requests_request.pb.h"

#include <algorithm>
#include "google/protobuf/io/coded_stream.h"
#include "google/protobuf/extension_set.h"
#include "google/protobuf/wire_format_lite.h"
#include "google/protobuf/io/zero_copy_stream_impl_lite.h"
#include "google/protobuf/generated_message_tctable_impl.h"
// @@protoc_insertion_point(includes)

// Must be included last.
#include "google/protobuf/port_def.inc"
PROTOBUF_PRAGMA_INIT_SEG
namespace _pb = ::google::protobuf;
namespace _pbi = ::google::protobuf::internal;
namespace _fl = ::google::protobuf::internal::field_layout;
namespace turms {
namespace client {
namespace model {
namespace proto {
        template <typename>
PROTOBUF_CONSTEXPR QueryFriendRequestsRequest::QueryFriendRequestsRequest(::_pbi::ConstantInitialized)
    : _impl_{
      /*decltype(_impl_._has_bits_)*/ {},
      /*decltype(_impl_._cached_size_)*/ {},
      /*decltype(_impl_.last_updated_date_)*/ ::int64_t{0},
      /*decltype(_impl_.are_sent_by_me_)*/ false,
    } {}
struct QueryFriendRequestsRequestDefaultTypeInternal {
  PROTOBUF_CONSTEXPR QueryFriendRequestsRequestDefaultTypeInternal() : _instance(::_pbi::ConstantInitialized{}) {}
  ~QueryFriendRequestsRequestDefaultTypeInternal() {}
  union {
    QueryFriendRequestsRequest _instance;
  };
};

PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT
    PROTOBUF_ATTRIBUTE_INIT_PRIORITY1 QueryFriendRequestsRequestDefaultTypeInternal _QueryFriendRequestsRequest_default_instance_;
}  // namespace proto
}  // namespace model
}  // namespace client
}  // namespace turms
namespace turms {
namespace client {
namespace model {
namespace proto {
// ===================================================================

class QueryFriendRequestsRequest::_Internal {
 public:
  using HasBits = decltype(std::declval<QueryFriendRequestsRequest>()._impl_._has_bits_);
  static constexpr ::int32_t kHasBitsOffset =
    8 * PROTOBUF_FIELD_OFFSET(QueryFriendRequestsRequest, _impl_._has_bits_);
  static void set_has_last_updated_date(HasBits* has_bits) {
    (*has_bits)[0] |= 1u;
  }
};

QueryFriendRequestsRequest::QueryFriendRequestsRequest(::google::protobuf::Arena* arena)
    : ::google::protobuf::MessageLite(arena) {
  SharedCtor(arena);
  // @@protoc_insertion_point(arena_constructor:turms.client.model.proto.QueryFriendRequestsRequest)
}
QueryFriendRequestsRequest::QueryFriendRequestsRequest(const QueryFriendRequestsRequest& from)
    : ::google::protobuf::MessageLite(), _impl_(from._impl_) {
  _internal_metadata_.MergeFrom<std::string>(
      from._internal_metadata_);
  // @@protoc_insertion_point(copy_constructor:turms.client.model.proto.QueryFriendRequestsRequest)
}
inline void QueryFriendRequestsRequest::SharedCtor(::_pb::Arena* arena) {
  (void)arena;
  new (&_impl_) Impl_{
      decltype(_impl_._has_bits_){},
      /*decltype(_impl_._cached_size_)*/ {},
      decltype(_impl_.last_updated_date_){::int64_t{0}},
      decltype(_impl_.are_sent_by_me_){false},
  };
}
QueryFriendRequestsRequest::~QueryFriendRequestsRequest() {
  // @@protoc_insertion_point(destructor:turms.client.model.proto.QueryFriendRequestsRequest)
  _internal_metadata_.Delete<std::string>();
  SharedDtor();
}
inline void QueryFriendRequestsRequest::SharedDtor() {
  ABSL_DCHECK(GetArenaForAllocation() == nullptr);
}
void QueryFriendRequestsRequest::SetCachedSize(int size) const {
  _impl_._cached_size_.Set(size);
}

PROTOBUF_NOINLINE void QueryFriendRequestsRequest::Clear() {
// @@protoc_insertion_point(message_clear_start:turms.client.model.proto.QueryFriendRequestsRequest)
  ::uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  _impl_.last_updated_date_ = ::int64_t{0};
  _impl_.are_sent_by_me_ = false;
  _impl_._has_bits_.Clear();
  _internal_metadata_.Clear<std::string>();
}

const char* QueryFriendRequestsRequest::_InternalParse(
    const char* ptr, ::_pbi::ParseContext* ctx) {
  ptr = ::_pbi::TcParser::ParseLoop(this, ptr, ctx, &_table_.header);
  return ptr;
}


PROTOBUF_CONSTINIT PROTOBUF_ATTRIBUTE_INIT_PRIORITY1
const ::_pbi::TcParseTable<1, 2, 0, 0, 2> QueryFriendRequestsRequest::_table_ = {
  {
    PROTOBUF_FIELD_OFFSET(QueryFriendRequestsRequest, _impl_._has_bits_),
    0, // no _extensions_
    2, 8,  // max_field_number, fast_idx_mask
    offsetof(decltype(_table_), field_lookup_table),
    4294967292,  // skipmap
    offsetof(decltype(_table_), field_entries),
    2,  // num_field_entries
    0,  // num_aux_entries
    offsetof(decltype(_table_), field_names),  // no aux_entries
    &_QueryFriendRequestsRequest_default_instance_._instance,
    ::_pbi::TcParser::GenericFallbackLite,  // fallback
  }, {{
    // optional int64 last_updated_date = 2;
    {::_pbi::TcParser::FastV64S1,
     {16, 0, 0, PROTOBUF_FIELD_OFFSET(QueryFriendRequestsRequest, _impl_.last_updated_date_)}},
    // bool are_sent_by_me = 1;
    {::_pbi::TcParser::FastV8S1,
     {8, 63, 0, PROTOBUF_FIELD_OFFSET(QueryFriendRequestsRequest, _impl_.are_sent_by_me_)}},
  }}, {{
    65535, 65535
  }}, {{
    // bool are_sent_by_me = 1;
    {PROTOBUF_FIELD_OFFSET(QueryFriendRequestsRequest, _impl_.are_sent_by_me_), -1, 0,
    (0 | ::_fl::kFcSingular | ::_fl::kBool)},
    // optional int64 last_updated_date = 2;
    {PROTOBUF_FIELD_OFFSET(QueryFriendRequestsRequest, _impl_.last_updated_date_), _Internal::kHasBitsOffset + 0, 0,
    (0 | ::_fl::kFcOptional | ::_fl::kInt64)},
  }},
  // no aux_entries
  {{
  }},
};

::uint8_t* QueryFriendRequestsRequest::_InternalSerialize(
    ::uint8_t* target,
    ::google::protobuf::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:turms.client.model.proto.QueryFriendRequestsRequest)
  ::uint32_t cached_has_bits = 0;
  (void)cached_has_bits;

  // bool are_sent_by_me = 1;
  if (this->_internal_are_sent_by_me() != 0) {
    target = stream->EnsureSpace(target);
    target = ::_pbi::WireFormatLite::WriteBoolToArray(
        1, this->_internal_are_sent_by_me(), target);
  }

  cached_has_bits = _impl_._has_bits_[0];
  // optional int64 last_updated_date = 2;
  if (cached_has_bits & 0x00000001u) {
    target = ::google::protobuf::internal::WireFormatLite::
        WriteInt64ToArrayWithField<2>(
            stream, this->_internal_last_updated_date(), target);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = stream->WriteRaw(
        _internal_metadata_.unknown_fields<std::string>(::google::protobuf::internal::GetEmptyString).data(),
        static_cast<int>(_internal_metadata_.unknown_fields<std::string>(::google::protobuf::internal::GetEmptyString).size()), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:turms.client.model.proto.QueryFriendRequestsRequest)
  return target;
}

::size_t QueryFriendRequestsRequest::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:turms.client.model.proto.QueryFriendRequestsRequest)
  ::size_t total_size = 0;

  ::uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // optional int64 last_updated_date = 2;
  cached_has_bits = _impl_._has_bits_[0];
  if (cached_has_bits & 0x00000001u) {
    total_size += ::_pbi::WireFormatLite::Int64SizePlusOne(
        this->_internal_last_updated_date());
  }

  // bool are_sent_by_me = 1;
  if (this->_internal_are_sent_by_me() != 0) {
    total_size += 2;
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    total_size += _internal_metadata_.unknown_fields<std::string>(::google::protobuf::internal::GetEmptyString).size();
  }
  int cached_size = ::_pbi::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

void QueryFriendRequestsRequest::CheckTypeAndMergeFrom(
    const ::google::protobuf::MessageLite& from) {
  MergeFrom(*::_pbi::DownCast<const QueryFriendRequestsRequest*>(
      &from));
}

void QueryFriendRequestsRequest::MergeFrom(const QueryFriendRequestsRequest& from) {
  QueryFriendRequestsRequest* const _this = this;
  // @@protoc_insertion_point(class_specific_merge_from_start:turms.client.model.proto.QueryFriendRequestsRequest)
  ABSL_DCHECK_NE(&from, _this);
  ::uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  if ((from._impl_._has_bits_[0] & 0x00000001u) != 0) {
    _this->_internal_set_last_updated_date(from._internal_last_updated_date());
  }
  if (from._internal_are_sent_by_me() != 0) {
    _this->_internal_set_are_sent_by_me(from._internal_are_sent_by_me());
  }
  _this->_internal_metadata_.MergeFrom<std::string>(from._internal_metadata_);
}

void QueryFriendRequestsRequest::CopyFrom(const QueryFriendRequestsRequest& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:turms.client.model.proto.QueryFriendRequestsRequest)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

PROTOBUF_NOINLINE bool QueryFriendRequestsRequest::IsInitialized() const {
  return true;
}

void QueryFriendRequestsRequest::InternalSwap(QueryFriendRequestsRequest* other) {
  using std::swap;
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  swap(_impl_._has_bits_[0], other->_impl_._has_bits_[0]);
  ::google::protobuf::internal::memswap<
      PROTOBUF_FIELD_OFFSET(QueryFriendRequestsRequest, _impl_.are_sent_by_me_)
      + sizeof(QueryFriendRequestsRequest::_impl_.are_sent_by_me_)
      - PROTOBUF_FIELD_OFFSET(QueryFriendRequestsRequest, _impl_.last_updated_date_)>(
          reinterpret_cast<char*>(&_impl_.last_updated_date_),
          reinterpret_cast<char*>(&other->_impl_.last_updated_date_));
}

std::string QueryFriendRequestsRequest::GetTypeName() const {
  return "turms.client.model.proto.QueryFriendRequestsRequest";
}

// @@protoc_insertion_point(namespace_scope)
}  // namespace proto
}  // namespace model
}  // namespace client
}  // namespace turms
namespace google {
namespace protobuf {
}  // namespace protobuf
}  // namespace google
// @@protoc_insertion_point(global_scope)
#include "google/protobuf/port_undef.inc"