// Generated by the protocol buffer compiler.  DO NOT EDIT!
// NO CHECKED-IN PROTOBUF GENCODE
// source: request/conversation/delete_conversation_settings_request.proto
// Protobuf C++ Version: 5.27.2

#include "turms/client/model/proto/request/conversation/delete_conversation_settings_request.pb.h"

#include <algorithm>
#include <type_traits>

#include "google/protobuf/extension_set.h"
#include "google/protobuf/generated_message_tctable_impl.h"
#include "google/protobuf/io/coded_stream.h"
#include "google/protobuf/io/zero_copy_stream_impl_lite.h"
#include "google/protobuf/wire_format_lite.h"
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

inline constexpr DeleteConversationSettingsRequest::Impl_::Impl_(
    ::_pbi::ConstantInitialized) noexcept
    : user_ids_{},
      _user_ids_cached_byte_size_{0},
      group_ids_{},
      _group_ids_cached_byte_size_{0},
      names_{},
      custom_attributes_{},
      _cached_size_{0} {
}

template <typename>
PROTOBUF_CONSTEXPR DeleteConversationSettingsRequest::DeleteConversationSettingsRequest(
    ::_pbi::ConstantInitialized)
    : _impl_(::_pbi::ConstantInitialized()) {
}
struct DeleteConversationSettingsRequestDefaultTypeInternal {
    PROTOBUF_CONSTEXPR DeleteConversationSettingsRequestDefaultTypeInternal()
        : _instance(::_pbi::ConstantInitialized{}) {
    }
    ~DeleteConversationSettingsRequestDefaultTypeInternal() {
    }
    union {
        DeleteConversationSettingsRequest _instance;
    };
};

PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT PROTOBUF_ATTRIBUTE_INIT_PRIORITY1
    DeleteConversationSettingsRequestDefaultTypeInternal
        _DeleteConversationSettingsRequest_default_instance_;
}  // namespace proto
}  // namespace model
}  // namespace client
}  // namespace turms
namespace turms {
namespace client {
namespace model {
namespace proto {
// ===================================================================

class DeleteConversationSettingsRequest::_Internal {
   public:
};

void DeleteConversationSettingsRequest::clear_custom_attributes() {
    ::google::protobuf::internal::TSanWrite(&_impl_);
    _impl_.custom_attributes_.Clear();
}
DeleteConversationSettingsRequest::DeleteConversationSettingsRequest(
    ::google::protobuf::Arena* arena)
    : ::google::protobuf::MessageLite(arena) {
    SharedCtor(arena);
    // @@protoc_insertion_point(arena_constructor:turms.client.model.proto.DeleteConversationSettingsRequest)
}
inline PROTOBUF_NDEBUG_INLINE DeleteConversationSettingsRequest::Impl_::Impl_(
    ::google::protobuf::internal::InternalVisibility visibility,
    ::google::protobuf::Arena* arena,
    const Impl_& from,
    const ::turms::client::model::proto::DeleteConversationSettingsRequest& from_msg)
    : user_ids_{visibility, arena, from.user_ids_},
      _user_ids_cached_byte_size_{0},
      group_ids_{visibility, arena, from.group_ids_},
      _group_ids_cached_byte_size_{0},
      names_{visibility, arena, from.names_},
      custom_attributes_{visibility, arena, from.custom_attributes_},
      _cached_size_{0} {
}

DeleteConversationSettingsRequest::DeleteConversationSettingsRequest(
    ::google::protobuf::Arena* arena, const DeleteConversationSettingsRequest& from)
    : ::google::protobuf::MessageLite(arena) {
    DeleteConversationSettingsRequest* const _this = this;
    (void)_this;
    _internal_metadata_.MergeFrom<std::string>(from._internal_metadata_);
    new (&_impl_) Impl_(internal_visibility(), arena, from._impl_, from);

    // @@protoc_insertion_point(copy_constructor:turms.client.model.proto.DeleteConversationSettingsRequest)
}
inline PROTOBUF_NDEBUG_INLINE DeleteConversationSettingsRequest::Impl_::Impl_(
    ::google::protobuf::internal::InternalVisibility visibility, ::google::protobuf::Arena* arena)
    : user_ids_{visibility, arena},
      _user_ids_cached_byte_size_{0},
      group_ids_{visibility, arena},
      _group_ids_cached_byte_size_{0},
      names_{visibility, arena},
      custom_attributes_{visibility, arena},
      _cached_size_{0} {
}

inline void DeleteConversationSettingsRequest::SharedCtor(::_pb::Arena* arena) {
    new (&_impl_) Impl_(internal_visibility(), arena);
}
DeleteConversationSettingsRequest::~DeleteConversationSettingsRequest() {
    // @@protoc_insertion_point(destructor:turms.client.model.proto.DeleteConversationSettingsRequest)
    _internal_metadata_.Delete<std::string>();
    SharedDtor();
}
inline void DeleteConversationSettingsRequest::SharedDtor() {
    ABSL_DCHECK(GetArena() == nullptr);
    _impl_.~Impl_();
}

const ::google::protobuf::MessageLite::ClassData* DeleteConversationSettingsRequest::GetClassData()
    const {
    PROTOBUF_CONSTINIT static const ClassDataLite<59> _data_ = {
        {
            &_table_.header,
            nullptr,  // OnDemandRegisterArenaDtor
            nullptr,  // IsInitialized
            PROTOBUF_FIELD_OFFSET(DeleteConversationSettingsRequest, _impl_._cached_size_),
            true,
        },
        "turms.client.model.proto.DeleteConversationSettingsRequest",
    };

    return _data_.base();
}
PROTOBUF_CONSTINIT PROTOBUF_ATTRIBUTE_INIT_PRIORITY1 const ::_pbi::TcParseTable<3, 4, 1, 72, 2>
    DeleteConversationSettingsRequest::_table_ = {
        {
            0,  // no _has_bits_
            0,  // no _extensions_
            15,
            56,  // max_field_number, fast_idx_mask
            offsetof(decltype(_table_), field_lookup_table),
            4294950904,  // skipmap
            offsetof(decltype(_table_), field_entries),
            4,  // num_field_entries
            1,  // num_aux_entries
            offsetof(decltype(_table_), aux_entries),
            &_DeleteConversationSettingsRequest_default_instance_._instance,
            nullptr,                                // post_loop_handler
            ::_pbi::TcParser::GenericFallbackLite,  // fallback
#ifdef PROTOBUF_PREFETCH_PARSE_TABLE
            ::_pbi::TcParser::GetTable<
                ::turms::client::model::proto::DeleteConversationSettingsRequest>(),  // to_prefetch
#endif  // PROTOBUF_PREFETCH_PARSE_TABLE
        },
        {{
            {::_pbi::TcParser::MiniParse, {}},
            // repeated int64 user_ids = 1;
            {::_pbi::TcParser::FastV64P1,
             {10,
              63,
              0,
              PROTOBUF_FIELD_OFFSET(DeleteConversationSettingsRequest, _impl_.user_ids_)}},
            // repeated int64 group_ids = 2;
            {::_pbi::TcParser::FastV64P1,
             {18,
              63,
              0,
              PROTOBUF_FIELD_OFFSET(DeleteConversationSettingsRequest, _impl_.group_ids_)}},
            // repeated string names = 3;
            {::_pbi::TcParser::FastUR1,
             {26, 63, 0, PROTOBUF_FIELD_OFFSET(DeleteConversationSettingsRequest, _impl_.names_)}},
            {::_pbi::TcParser::MiniParse, {}},
            {::_pbi::TcParser::MiniParse, {}},
            {::_pbi::TcParser::MiniParse, {}},
            // repeated .turms.client.model.proto.Value custom_attributes = 15;
            {::_pbi::TcParser::FastMtR1,
             {122,
              63,
              0,
              PROTOBUF_FIELD_OFFSET(DeleteConversationSettingsRequest, _impl_.custom_attributes_)}},
        }},
        {{65535, 65535}},
        {{
            // repeated int64 user_ids = 1;
            {PROTOBUF_FIELD_OFFSET(DeleteConversationSettingsRequest, _impl_.user_ids_),
             0,
             0,
             (0 | ::_fl::kFcRepeated | ::_fl::kPackedInt64)},
            // repeated int64 group_ids = 2;
            {PROTOBUF_FIELD_OFFSET(DeleteConversationSettingsRequest, _impl_.group_ids_),
             0,
             0,
             (0 | ::_fl::kFcRepeated | ::_fl::kPackedInt64)},
            // repeated string names = 3;
            {PROTOBUF_FIELD_OFFSET(DeleteConversationSettingsRequest, _impl_.names_),
             0,
             0,
             (0 | ::_fl::kFcRepeated | ::_fl::kUtf8String | ::_fl::kRepSString)},
            // repeated .turms.client.model.proto.Value custom_attributes = 15;
            {PROTOBUF_FIELD_OFFSET(DeleteConversationSettingsRequest, _impl_.custom_attributes_),
             0,
             0,
             (0 | ::_fl::kFcRepeated | ::_fl::kMessage | ::_fl::kTvTable)},
        }},
        {{
            {::_pbi::TcParser::GetTable<::turms::client::model::proto::Value>()},
        }},
        {{"\72\0\0\5\0\0\0\0"
          "turms.client.model.proto.DeleteConversationSettingsRequest"
          "names"}},
};

PROTOBUF_NOINLINE void DeleteConversationSettingsRequest::Clear() {
    // @@protoc_insertion_point(message_clear_start:turms.client.model.proto.DeleteConversationSettingsRequest)
    ::google::protobuf::internal::TSanWrite(&_impl_);
    ::uint32_t cached_has_bits = 0;
    // Prevent compiler warnings about cached_has_bits being unused
    (void)cached_has_bits;

    _impl_.user_ids_.Clear();
    _impl_.group_ids_.Clear();
    _impl_.names_.Clear();
    _impl_.custom_attributes_.Clear();
    _internal_metadata_.Clear<std::string>();
}

::uint8_t* DeleteConversationSettingsRequest::_InternalSerialize(
    ::uint8_t* target, ::google::protobuf::io::EpsCopyOutputStream* stream) const {
    // @@protoc_insertion_point(serialize_to_array_start:turms.client.model.proto.DeleteConversationSettingsRequest)
    ::uint32_t cached_has_bits = 0;
    (void)cached_has_bits;

    // repeated int64 user_ids = 1;
    {
        int byte_size = _impl_._user_ids_cached_byte_size_.Get();
        if (byte_size > 0) {
            target = stream->WriteInt64Packed(1, _internal_user_ids(), byte_size, target);
        }
    }

    // repeated int64 group_ids = 2;
    {
        int byte_size = _impl_._group_ids_cached_byte_size_.Get();
        if (byte_size > 0) {
            target = stream->WriteInt64Packed(2, _internal_group_ids(), byte_size, target);
        }
    }

    // repeated string names = 3;
    for (int i = 0, n = this->_internal_names_size(); i < n; ++i) {
        const auto& s = this->_internal_names().Get(i);
        ::google::protobuf::internal::WireFormatLite::VerifyUtf8String(
            s.data(),
            static_cast<int>(s.length()),
            ::google::protobuf::internal::WireFormatLite::SERIALIZE,
            "turms.client.model.proto.DeleteConversationSettingsRequest.names");
        target = stream->WriteString(3, s, target);
    }

    // repeated .turms.client.model.proto.Value custom_attributes = 15;
    for (unsigned i = 0, n = static_cast<unsigned>(this->_internal_custom_attributes_size()); i < n;
         i++) {
        const auto& repfield = this->_internal_custom_attributes().Get(i);
        target = ::google::protobuf::internal::WireFormatLite::InternalWriteMessage(
            15, repfield, repfield.GetCachedSize(), target, stream);
    }

    if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
        target = stream->WriteRaw(
            _internal_metadata_
                .unknown_fields<std::string>(::google::protobuf::internal::GetEmptyString)
                .data(),
            static_cast<int>(
                _internal_metadata_
                    .unknown_fields<std::string>(::google::protobuf::internal::GetEmptyString)
                    .size()),
            target);
    }
    // @@protoc_insertion_point(serialize_to_array_end:turms.client.model.proto.DeleteConversationSettingsRequest)
    return target;
}

::size_t DeleteConversationSettingsRequest::ByteSizeLong() const {
    // @@protoc_insertion_point(message_byte_size_start:turms.client.model.proto.DeleteConversationSettingsRequest)
    ::size_t total_size = 0;

    ::uint32_t cached_has_bits = 0;
    // Prevent compiler warnings about cached_has_bits being unused
    (void)cached_has_bits;

    ::_pbi::Prefetch5LinesFrom7Lines(reinterpret_cast<const void*>(this));
    // repeated int64 user_ids = 1;
    {
        std::size_t data_size = ::_pbi::WireFormatLite::Int64Size(this->_internal_user_ids());
        _impl_._user_ids_cached_byte_size_.Set(::_pbi::ToCachedSize(data_size));
        std::size_t tag_size =
            data_size == 0 ? 0
                           : 1 + ::_pbi::WireFormatLite::Int32Size(static_cast<int32_t>(data_size));
        total_size += tag_size + data_size;
    }
    // repeated int64 group_ids = 2;
    {
        std::size_t data_size = ::_pbi::WireFormatLite::Int64Size(this->_internal_group_ids());
        _impl_._group_ids_cached_byte_size_.Set(::_pbi::ToCachedSize(data_size));
        std::size_t tag_size =
            data_size == 0 ? 0
                           : 1 + ::_pbi::WireFormatLite::Int32Size(static_cast<int32_t>(data_size));
        total_size += tag_size + data_size;
    }
    // repeated string names = 3;
    total_size += 1 * ::google::protobuf::internal::FromIntSize(_internal_names().size());
    for (int i = 0, n = _internal_names().size(); i < n; ++i) {
        total_size +=
            ::google::protobuf::internal::WireFormatLite::StringSize(_internal_names().Get(i));
    }
    // repeated .turms.client.model.proto.Value custom_attributes = 15;
    total_size += 1UL * this->_internal_custom_attributes_size();
    for (const auto& msg : this->_internal_custom_attributes()) {
        total_size += ::google::protobuf::internal::WireFormatLite::MessageSize(msg);
    }
    if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
        total_size += _internal_metadata_
                          .unknown_fields<std::string>(::google::protobuf::internal::GetEmptyString)
                          .size();
    }
    _impl_._cached_size_.Set(::_pbi::ToCachedSize(total_size));
    return total_size;
}

void DeleteConversationSettingsRequest::CheckTypeAndMergeFrom(
    const ::google::protobuf::MessageLite& from) {
    MergeFrom(*::_pbi::DownCast<const DeleteConversationSettingsRequest*>(&from));
}

void DeleteConversationSettingsRequest::MergeFrom(const DeleteConversationSettingsRequest& from) {
    DeleteConversationSettingsRequest* const _this = this;
    // @@protoc_insertion_point(class_specific_merge_from_start:turms.client.model.proto.DeleteConversationSettingsRequest)
    ABSL_DCHECK_NE(&from, _this);
    ::uint32_t cached_has_bits = 0;
    (void)cached_has_bits;

    _this->_internal_mutable_user_ids()->MergeFrom(from._internal_user_ids());
    _this->_internal_mutable_group_ids()->MergeFrom(from._internal_group_ids());
    _this->_internal_mutable_names()->MergeFrom(from._internal_names());
    _this->_internal_mutable_custom_attributes()->MergeFrom(from._internal_custom_attributes());
    _this->_internal_metadata_.MergeFrom<std::string>(from._internal_metadata_);
}

void DeleteConversationSettingsRequest::CopyFrom(const DeleteConversationSettingsRequest& from) {
    // @@protoc_insertion_point(class_specific_copy_from_start:turms.client.model.proto.DeleteConversationSettingsRequest)
    if (&from == this)
        return;
    Clear();
    MergeFrom(from);
}

void DeleteConversationSettingsRequest::InternalSwap(
    DeleteConversationSettingsRequest* PROTOBUF_RESTRICT other) {
    using std::swap;
    _internal_metadata_.InternalSwap(&other->_internal_metadata_);
    _impl_.user_ids_.InternalSwap(&other->_impl_.user_ids_);
    _impl_.group_ids_.InternalSwap(&other->_impl_.group_ids_);
    _impl_.names_.InternalSwap(&other->_impl_.names_);
    _impl_.custom_attributes_.InternalSwap(&other->_impl_.custom_attributes_);
}

// @@protoc_insertion_point(namespace_scope)
}  // namespace proto
}  // namespace model
}  // namespace client
}  // namespace turms
namespace google {
namespace protobuf {}  // namespace protobuf
}  // namespace google
// @@protoc_insertion_point(global_scope)
#include "google/protobuf/port_undef.inc"