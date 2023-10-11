// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: request/group/enrollment/query_group_join_questions_request.proto

#include "turms/client/model/proto/request/group/enrollment/query_group_join_questions_request.pb.h"

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
PROTOBUF_CONSTEXPR QueryGroupJoinQuestionsRequest::QueryGroupJoinQuestionsRequest(::_pbi::ConstantInitialized)
    : _impl_{
      /*decltype(_impl_._has_bits_)*/ {},
      /*decltype(_impl_._cached_size_)*/ {},
      /*decltype(_impl_.group_id_)*/ ::int64_t{0},
      /*decltype(_impl_.last_updated_date_)*/ ::int64_t{0},
      /*decltype(_impl_.with_answers_)*/ false,
    } {}
struct QueryGroupJoinQuestionsRequestDefaultTypeInternal {
  PROTOBUF_CONSTEXPR QueryGroupJoinQuestionsRequestDefaultTypeInternal() : _instance(::_pbi::ConstantInitialized{}) {}
  ~QueryGroupJoinQuestionsRequestDefaultTypeInternal() {}
  union {
    QueryGroupJoinQuestionsRequest _instance;
  };
};

PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT
    PROTOBUF_ATTRIBUTE_INIT_PRIORITY1 QueryGroupJoinQuestionsRequestDefaultTypeInternal _QueryGroupJoinQuestionsRequest_default_instance_;
}  // namespace proto
}  // namespace model
}  // namespace client
}  // namespace turms
namespace turms {
namespace client {
namespace model {
namespace proto {
// ===================================================================

class QueryGroupJoinQuestionsRequest::_Internal {
 public:
  using HasBits = decltype(std::declval<QueryGroupJoinQuestionsRequest>()._impl_._has_bits_);
  static constexpr ::int32_t kHasBitsOffset =
    8 * PROTOBUF_FIELD_OFFSET(QueryGroupJoinQuestionsRequest, _impl_._has_bits_);
  static void set_has_last_updated_date(HasBits* has_bits) {
    (*has_bits)[0] |= 1u;
  }
};

QueryGroupJoinQuestionsRequest::QueryGroupJoinQuestionsRequest(::google::protobuf::Arena* arena)
    : ::google::protobuf::MessageLite(arena) {
  SharedCtor(arena);
  // @@protoc_insertion_point(arena_constructor:turms.client.model.proto.QueryGroupJoinQuestionsRequest)
}
QueryGroupJoinQuestionsRequest::QueryGroupJoinQuestionsRequest(const QueryGroupJoinQuestionsRequest& from)
    : ::google::protobuf::MessageLite(), _impl_(from._impl_) {
  _internal_metadata_.MergeFrom<std::string>(
      from._internal_metadata_);
  // @@protoc_insertion_point(copy_constructor:turms.client.model.proto.QueryGroupJoinQuestionsRequest)
}
inline void QueryGroupJoinQuestionsRequest::SharedCtor(::_pb::Arena* arena) {
  (void)arena;
  new (&_impl_) Impl_{
      decltype(_impl_._has_bits_){},
      /*decltype(_impl_._cached_size_)*/ {},
      decltype(_impl_.group_id_){::int64_t{0}},
      decltype(_impl_.last_updated_date_){::int64_t{0}},
      decltype(_impl_.with_answers_){false},
  };
}
QueryGroupJoinQuestionsRequest::~QueryGroupJoinQuestionsRequest() {
  // @@protoc_insertion_point(destructor:turms.client.model.proto.QueryGroupJoinQuestionsRequest)
  _internal_metadata_.Delete<std::string>();
  SharedDtor();
}
inline void QueryGroupJoinQuestionsRequest::SharedDtor() {
  ABSL_DCHECK(GetArenaForAllocation() == nullptr);
}
void QueryGroupJoinQuestionsRequest::SetCachedSize(int size) const {
  _impl_._cached_size_.Set(size);
}

PROTOBUF_NOINLINE void QueryGroupJoinQuestionsRequest::Clear() {
// @@protoc_insertion_point(message_clear_start:turms.client.model.proto.QueryGroupJoinQuestionsRequest)
  ::uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  _impl_.group_id_ = ::int64_t{0};
  _impl_.last_updated_date_ = ::int64_t{0};
  _impl_.with_answers_ = false;
  _impl_._has_bits_.Clear();
  _internal_metadata_.Clear<std::string>();
}

const char* QueryGroupJoinQuestionsRequest::_InternalParse(
    const char* ptr, ::_pbi::ParseContext* ctx) {
  ptr = ::_pbi::TcParser::ParseLoop(this, ptr, ctx, &_table_.header);
  return ptr;
}


PROTOBUF_CONSTINIT PROTOBUF_ATTRIBUTE_INIT_PRIORITY1
const ::_pbi::TcParseTable<2, 3, 0, 0, 2> QueryGroupJoinQuestionsRequest::_table_ = {
  {
    PROTOBUF_FIELD_OFFSET(QueryGroupJoinQuestionsRequest, _impl_._has_bits_),
    0, // no _extensions_
    3, 24,  // max_field_number, fast_idx_mask
    offsetof(decltype(_table_), field_lookup_table),
    4294967288,  // skipmap
    offsetof(decltype(_table_), field_entries),
    3,  // num_field_entries
    0,  // num_aux_entries
    offsetof(decltype(_table_), field_names),  // no aux_entries
    &_QueryGroupJoinQuestionsRequest_default_instance_._instance,
    ::_pbi::TcParser::GenericFallbackLite,  // fallback
  }, {{
    {::_pbi::TcParser::MiniParse, {}},
    // int64 group_id = 1;
    {::_pbi::TcParser::FastV64S1,
     {8, 63, 0, PROTOBUF_FIELD_OFFSET(QueryGroupJoinQuestionsRequest, _impl_.group_id_)}},
    // bool with_answers = 2;
    {::_pbi::TcParser::FastV8S1,
     {16, 63, 0, PROTOBUF_FIELD_OFFSET(QueryGroupJoinQuestionsRequest, _impl_.with_answers_)}},
    // optional int64 last_updated_date = 3;
    {::_pbi::TcParser::FastV64S1,
     {24, 0, 0, PROTOBUF_FIELD_OFFSET(QueryGroupJoinQuestionsRequest, _impl_.last_updated_date_)}},
  }}, {{
    65535, 65535
  }}, {{
    // int64 group_id = 1;
    {PROTOBUF_FIELD_OFFSET(QueryGroupJoinQuestionsRequest, _impl_.group_id_), -1, 0,
    (0 | ::_fl::kFcSingular | ::_fl::kInt64)},
    // bool with_answers = 2;
    {PROTOBUF_FIELD_OFFSET(QueryGroupJoinQuestionsRequest, _impl_.with_answers_), -1, 0,
    (0 | ::_fl::kFcSingular | ::_fl::kBool)},
    // optional int64 last_updated_date = 3;
    {PROTOBUF_FIELD_OFFSET(QueryGroupJoinQuestionsRequest, _impl_.last_updated_date_), _Internal::kHasBitsOffset + 0, 0,
    (0 | ::_fl::kFcOptional | ::_fl::kInt64)},
  }},
  // no aux_entries
  {{
  }},
};

::uint8_t* QueryGroupJoinQuestionsRequest::_InternalSerialize(
    ::uint8_t* target,
    ::google::protobuf::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:turms.client.model.proto.QueryGroupJoinQuestionsRequest)
  ::uint32_t cached_has_bits = 0;
  (void)cached_has_bits;

  // int64 group_id = 1;
  if (this->_internal_group_id() != 0) {
    target = ::google::protobuf::internal::WireFormatLite::
        WriteInt64ToArrayWithField<1>(
            stream, this->_internal_group_id(), target);
  }

  // bool with_answers = 2;
  if (this->_internal_with_answers() != 0) {
    target = stream->EnsureSpace(target);
    target = ::_pbi::WireFormatLite::WriteBoolToArray(
        2, this->_internal_with_answers(), target);
  }

  cached_has_bits = _impl_._has_bits_[0];
  // optional int64 last_updated_date = 3;
  if (cached_has_bits & 0x00000001u) {
    target = ::google::protobuf::internal::WireFormatLite::
        WriteInt64ToArrayWithField<3>(
            stream, this->_internal_last_updated_date(), target);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = stream->WriteRaw(
        _internal_metadata_.unknown_fields<std::string>(::google::protobuf::internal::GetEmptyString).data(),
        static_cast<int>(_internal_metadata_.unknown_fields<std::string>(::google::protobuf::internal::GetEmptyString).size()), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:turms.client.model.proto.QueryGroupJoinQuestionsRequest)
  return target;
}

::size_t QueryGroupJoinQuestionsRequest::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:turms.client.model.proto.QueryGroupJoinQuestionsRequest)
  ::size_t total_size = 0;

  ::uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // int64 group_id = 1;
  if (this->_internal_group_id() != 0) {
    total_size += ::_pbi::WireFormatLite::Int64SizePlusOne(
        this->_internal_group_id());
  }

  // optional int64 last_updated_date = 3;
  cached_has_bits = _impl_._has_bits_[0];
  if (cached_has_bits & 0x00000001u) {
    total_size += ::_pbi::WireFormatLite::Int64SizePlusOne(
        this->_internal_last_updated_date());
  }

  // bool with_answers = 2;
  if (this->_internal_with_answers() != 0) {
    total_size += 2;
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    total_size += _internal_metadata_.unknown_fields<std::string>(::google::protobuf::internal::GetEmptyString).size();
  }
  int cached_size = ::_pbi::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

void QueryGroupJoinQuestionsRequest::CheckTypeAndMergeFrom(
    const ::google::protobuf::MessageLite& from) {
  MergeFrom(*::_pbi::DownCast<const QueryGroupJoinQuestionsRequest*>(
      &from));
}

void QueryGroupJoinQuestionsRequest::MergeFrom(const QueryGroupJoinQuestionsRequest& from) {
  QueryGroupJoinQuestionsRequest* const _this = this;
  // @@protoc_insertion_point(class_specific_merge_from_start:turms.client.model.proto.QueryGroupJoinQuestionsRequest)
  ABSL_DCHECK_NE(&from, _this);
  ::uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  if (from._internal_group_id() != 0) {
    _this->_internal_set_group_id(from._internal_group_id());
  }
  if ((from._impl_._has_bits_[0] & 0x00000001u) != 0) {
    _this->_internal_set_last_updated_date(from._internal_last_updated_date());
  }
  if (from._internal_with_answers() != 0) {
    _this->_internal_set_with_answers(from._internal_with_answers());
  }
  _this->_internal_metadata_.MergeFrom<std::string>(from._internal_metadata_);
}

void QueryGroupJoinQuestionsRequest::CopyFrom(const QueryGroupJoinQuestionsRequest& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:turms.client.model.proto.QueryGroupJoinQuestionsRequest)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

PROTOBUF_NOINLINE bool QueryGroupJoinQuestionsRequest::IsInitialized() const {
  return true;
}

void QueryGroupJoinQuestionsRequest::InternalSwap(QueryGroupJoinQuestionsRequest* other) {
  using std::swap;
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  swap(_impl_._has_bits_[0], other->_impl_._has_bits_[0]);
  ::google::protobuf::internal::memswap<
      PROTOBUF_FIELD_OFFSET(QueryGroupJoinQuestionsRequest, _impl_.with_answers_)
      + sizeof(QueryGroupJoinQuestionsRequest::_impl_.with_answers_)
      - PROTOBUF_FIELD_OFFSET(QueryGroupJoinQuestionsRequest, _impl_.group_id_)>(
          reinterpret_cast<char*>(&_impl_.group_id_),
          reinterpret_cast<char*>(&other->_impl_.group_id_));
}

std::string QueryGroupJoinQuestionsRequest::GetTypeName() const {
  return "turms.client.model.proto.QueryGroupJoinQuestionsRequest";
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