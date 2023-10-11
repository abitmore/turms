// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: model/user/user_friend_request.proto

#ifndef GOOGLE_PROTOBUF_INCLUDED_model_2fuser_2fuser_5ffriend_5frequest_2eproto_2epb_2eh
#define GOOGLE_PROTOBUF_INCLUDED_model_2fuser_2fuser_5ffriend_5frequest_2eproto_2epb_2eh

#include <limits>
#include <string>
#include <type_traits>

#include "google/protobuf/port_def.inc"
#if PROTOBUF_VERSION < 4024000
#error "This file was generated by a newer version of protoc which is"
#error "incompatible with your Protocol Buffer headers. Please update"
#error "your headers."
#endif  // PROTOBUF_VERSION

#if 4024000 < PROTOBUF_MIN_PROTOC_VERSION
#error "This file was generated by an older version of protoc which is"
#error "incompatible with your Protocol Buffer headers. Please"
#error "regenerate this file with a newer version of protoc."
#endif  // PROTOBUF_MIN_PROTOC_VERSION
#include "google/protobuf/port_undef.inc"
#include "google/protobuf/io/coded_stream.h"
#include "google/protobuf/arena.h"
#include "google/protobuf/arenastring.h"
#include "google/protobuf/generated_message_tctable_decl.h"
#include "google/protobuf/generated_message_util.h"
#include "google/protobuf/metadata_lite.h"
#include "google/protobuf/message_lite.h"
#include "google/protobuf/repeated_field.h"  // IWYU pragma: export
#include "google/protobuf/extension_set.h"  // IWYU pragma: export
#include "turms/client/model/proto/constant/request_status.pb.h"
// @@protoc_insertion_point(includes)

// Must be included last.
#include "google/protobuf/port_def.inc"

#define PROTOBUF_INTERNAL_EXPORT_model_2fuser_2fuser_5ffriend_5frequest_2eproto

namespace google {
namespace protobuf {
namespace internal {
class AnyMetadata;
}  // namespace internal
}  // namespace protobuf
}  // namespace google

// Internal implementation detail -- do not use these members.
struct TableStruct_model_2fuser_2fuser_5ffriend_5frequest_2eproto {
  static const ::uint32_t offsets[];
};
namespace turms {
namespace client {
namespace model {
namespace proto {
class UserFriendRequest;
struct UserFriendRequestDefaultTypeInternal;
extern UserFriendRequestDefaultTypeInternal _UserFriendRequest_default_instance_;
}  // namespace proto
}  // namespace model
}  // namespace client
}  // namespace turms
namespace google {
namespace protobuf {
}  // namespace protobuf
}  // namespace google

namespace turms {
namespace client {
namespace model {
namespace proto {

// ===================================================================


// -------------------------------------------------------------------

class UserFriendRequest final :
    public ::google::protobuf::MessageLite /* @@protoc_insertion_point(class_definition:turms.client.model.proto.UserFriendRequest) */ {
 public:
  inline UserFriendRequest() : UserFriendRequest(nullptr) {}
  ~UserFriendRequest() override;
  template<typename = void>
  explicit PROTOBUF_CONSTEXPR UserFriendRequest(::google::protobuf::internal::ConstantInitialized);

  UserFriendRequest(const UserFriendRequest& from);
  UserFriendRequest(UserFriendRequest&& from) noexcept
    : UserFriendRequest() {
    *this = ::std::move(from);
  }

  inline UserFriendRequest& operator=(const UserFriendRequest& from) {
    CopyFrom(from);
    return *this;
  }
  inline UserFriendRequest& operator=(UserFriendRequest&& from) noexcept {
    if (this == &from) return *this;
    if (GetOwningArena() == from.GetOwningArena()
  #ifdef PROTOBUF_FORCE_COPY_IN_MOVE
        && GetOwningArena() != nullptr
  #endif  // !PROTOBUF_FORCE_COPY_IN_MOVE
    ) {
      InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  inline const std::string& unknown_fields() const {
    return _internal_metadata_.unknown_fields<std::string>(::google::protobuf::internal::GetEmptyString);
  }
  inline std::string* mutable_unknown_fields() {
    return _internal_metadata_.mutable_unknown_fields<std::string>();
  }

  static const UserFriendRequest& default_instance() {
    return *internal_default_instance();
  }
  static inline const UserFriendRequest* internal_default_instance() {
    return reinterpret_cast<const UserFriendRequest*>(
               &_UserFriendRequest_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    0;

  friend void swap(UserFriendRequest& a, UserFriendRequest& b) {
    a.Swap(&b);
  }
  inline void Swap(UserFriendRequest* other) {
    if (other == this) return;
  #ifdef PROTOBUF_FORCE_COPY_IN_SWAP
    if (GetOwningArena() != nullptr &&
        GetOwningArena() == other->GetOwningArena()) {
   #else  // PROTOBUF_FORCE_COPY_IN_SWAP
    if (GetOwningArena() == other->GetOwningArena()) {
  #endif  // !PROTOBUF_FORCE_COPY_IN_SWAP
      InternalSwap(other);
    } else {
      ::google::protobuf::internal::GenericSwap(this, other);
    }
  }
  void UnsafeArenaSwap(UserFriendRequest* other) {
    if (other == this) return;
    ABSL_DCHECK(GetOwningArena() == other->GetOwningArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  UserFriendRequest* New(::google::protobuf::Arena* arena = nullptr) const final {
    return CreateMaybeMessage<UserFriendRequest>(arena);
  }
  void CheckTypeAndMergeFrom(const ::google::protobuf::MessageLite& from)  final;
  void CopyFrom(const UserFriendRequest& from);
  void MergeFrom(const UserFriendRequest& from);
  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
  bool IsInitialized() const final;

  ::size_t ByteSizeLong() const final;
  const char* _InternalParse(const char* ptr, ::google::protobuf::internal::ParseContext* ctx) final;
  ::uint8_t* _InternalSerialize(
      ::uint8_t* target, ::google::protobuf::io::EpsCopyOutputStream* stream) const final;
  int GetCachedSize() const final { return _impl_._cached_size_.Get(); }

  private:
  void SharedCtor(::google::protobuf::Arena* arena);
  void SharedDtor();
  void SetCachedSize(int size) const;
  void InternalSwap(UserFriendRequest* other);

  private:
  friend class ::google::protobuf::internal::AnyMetadata;
  static ::absl::string_view FullMessageName() {
    return "turms.client.model.proto.UserFriendRequest";
  }
  protected:
  explicit UserFriendRequest(::google::protobuf::Arena* arena);
  public:

  std::string GetTypeName() const final;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  enum : int {
    kContentFieldNumber = 3,
    kReasonFieldNumber = 5,
    kIdFieldNumber = 1,
    kCreationDateFieldNumber = 2,
    kExpirationDateFieldNumber = 6,
    kRequesterIdFieldNumber = 7,
    kRecipientIdFieldNumber = 8,
    kRequestStatusFieldNumber = 4,
  };
  // optional string content = 3;
  bool has_content() const;
  void clear_content() ;
  const std::string& content() const;
  template <typename Arg_ = const std::string&, typename... Args_>
  void set_content(Arg_&& arg, Args_... args);
  std::string* mutable_content();
  PROTOBUF_NODISCARD std::string* release_content();
  void set_allocated_content(std::string* ptr);

  private:
  const std::string& _internal_content() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_content(
      const std::string& value);
  std::string* _internal_mutable_content();

  public:
  // optional string reason = 5;
  bool has_reason() const;
  void clear_reason() ;
  const std::string& reason() const;
  template <typename Arg_ = const std::string&, typename... Args_>
  void set_reason(Arg_&& arg, Args_... args);
  std::string* mutable_reason();
  PROTOBUF_NODISCARD std::string* release_reason();
  void set_allocated_reason(std::string* ptr);

  private:
  const std::string& _internal_reason() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_reason(
      const std::string& value);
  std::string* _internal_mutable_reason();

  public:
  // optional int64 id = 1;
  bool has_id() const;
  void clear_id() ;
  ::int64_t id() const;
  void set_id(::int64_t value);

  private:
  ::int64_t _internal_id() const;
  void _internal_set_id(::int64_t value);

  public:
  // optional int64 creation_date = 2;
  bool has_creation_date() const;
  void clear_creation_date() ;
  ::int64_t creation_date() const;
  void set_creation_date(::int64_t value);

  private:
  ::int64_t _internal_creation_date() const;
  void _internal_set_creation_date(::int64_t value);

  public:
  // optional int64 expiration_date = 6;
  bool has_expiration_date() const;
  void clear_expiration_date() ;
  ::int64_t expiration_date() const;
  void set_expiration_date(::int64_t value);

  private:
  ::int64_t _internal_expiration_date() const;
  void _internal_set_expiration_date(::int64_t value);

  public:
  // optional int64 requester_id = 7;
  bool has_requester_id() const;
  void clear_requester_id() ;
  ::int64_t requester_id() const;
  void set_requester_id(::int64_t value);

  private:
  ::int64_t _internal_requester_id() const;
  void _internal_set_requester_id(::int64_t value);

  public:
  // optional int64 recipient_id = 8;
  bool has_recipient_id() const;
  void clear_recipient_id() ;
  ::int64_t recipient_id() const;
  void set_recipient_id(::int64_t value);

  private:
  ::int64_t _internal_recipient_id() const;
  void _internal_set_recipient_id(::int64_t value);

  public:
  // optional .turms.client.model.proto.RequestStatus request_status = 4;
  bool has_request_status() const;
  void clear_request_status() ;
  ::turms::client::model::proto::RequestStatus request_status() const;
  void set_request_status(::turms::client::model::proto::RequestStatus value);

  private:
  ::turms::client::model::proto::RequestStatus _internal_request_status() const;
  void _internal_set_request_status(::turms::client::model::proto::RequestStatus value);

  public:
  // @@protoc_insertion_point(class_scope:turms.client.model.proto.UserFriendRequest)
 private:
  class _Internal;

  friend class ::google::protobuf::internal::TcParser;
  static const ::google::protobuf::internal::TcParseTable<3, 8, 0, 72, 2> _table_;
  template <typename T> friend class ::google::protobuf::Arena::InternalHelper;
  typedef void InternalArenaConstructable_;
  typedef void DestructorSkippable_;
  struct Impl_ {
    ::google::protobuf::internal::HasBits<1> _has_bits_;
    mutable ::google::protobuf::internal::CachedSize _cached_size_;
    ::google::protobuf::internal::ArenaStringPtr content_;
    ::google::protobuf::internal::ArenaStringPtr reason_;
    ::int64_t id_;
    ::int64_t creation_date_;
    ::int64_t expiration_date_;
    ::int64_t requester_id_;
    ::int64_t recipient_id_;
    int request_status_;
    PROTOBUF_TSAN_DECLARE_MEMBER;
  };
  union { Impl_ _impl_; };
  friend struct ::TableStruct_model_2fuser_2fuser_5ffriend_5frequest_2eproto;
};

// ===================================================================




// ===================================================================


#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif  // __GNUC__
// -------------------------------------------------------------------

// UserFriendRequest

// optional int64 id = 1;
inline bool UserFriendRequest::has_id() const {
  bool value = (_impl_._has_bits_[0] & 0x00000004u) != 0;
  return value;
}
inline void UserFriendRequest::clear_id() {
  _impl_.id_ = ::int64_t{0};
  _impl_._has_bits_[0] &= ~0x00000004u;
}
inline ::int64_t UserFriendRequest::id() const {
  // @@protoc_insertion_point(field_get:turms.client.model.proto.UserFriendRequest.id)
  return _internal_id();
}
inline void UserFriendRequest::set_id(::int64_t value) {
  _internal_set_id(value);
  // @@protoc_insertion_point(field_set:turms.client.model.proto.UserFriendRequest.id)
}
inline ::int64_t UserFriendRequest::_internal_id() const {
  PROTOBUF_TSAN_READ(&_impl_._tsan_detect_race);
  return _impl_.id_;
}
inline void UserFriendRequest::_internal_set_id(::int64_t value) {
  PROTOBUF_TSAN_WRITE(&_impl_._tsan_detect_race);
  _impl_._has_bits_[0] |= 0x00000004u;
  _impl_.id_ = value;
}

// optional int64 creation_date = 2;
inline bool UserFriendRequest::has_creation_date() const {
  bool value = (_impl_._has_bits_[0] & 0x00000008u) != 0;
  return value;
}
inline void UserFriendRequest::clear_creation_date() {
  _impl_.creation_date_ = ::int64_t{0};
  _impl_._has_bits_[0] &= ~0x00000008u;
}
inline ::int64_t UserFriendRequest::creation_date() const {
  // @@protoc_insertion_point(field_get:turms.client.model.proto.UserFriendRequest.creation_date)
  return _internal_creation_date();
}
inline void UserFriendRequest::set_creation_date(::int64_t value) {
  _internal_set_creation_date(value);
  // @@protoc_insertion_point(field_set:turms.client.model.proto.UserFriendRequest.creation_date)
}
inline ::int64_t UserFriendRequest::_internal_creation_date() const {
  PROTOBUF_TSAN_READ(&_impl_._tsan_detect_race);
  return _impl_.creation_date_;
}
inline void UserFriendRequest::_internal_set_creation_date(::int64_t value) {
  PROTOBUF_TSAN_WRITE(&_impl_._tsan_detect_race);
  _impl_._has_bits_[0] |= 0x00000008u;
  _impl_.creation_date_ = value;
}

// optional string content = 3;
inline bool UserFriendRequest::has_content() const {
  bool value = (_impl_._has_bits_[0] & 0x00000001u) != 0;
  return value;
}
inline void UserFriendRequest::clear_content() {
  _impl_.content_.ClearToEmpty();
  _impl_._has_bits_[0] &= ~0x00000001u;
}
inline const std::string& UserFriendRequest::content() const {
  // @@protoc_insertion_point(field_get:turms.client.model.proto.UserFriendRequest.content)
  return _internal_content();
}
template <typename Arg_, typename... Args_>
inline PROTOBUF_ALWAYS_INLINE void UserFriendRequest::set_content(Arg_&& arg,
                                                     Args_... args) {
  PROTOBUF_TSAN_WRITE(&_impl_._tsan_detect_race);
  _impl_._has_bits_[0] |= 0x00000001u;
  _impl_.content_.Set(static_cast<Arg_&&>(arg), args..., GetArenaForAllocation());
  // @@protoc_insertion_point(field_set:turms.client.model.proto.UserFriendRequest.content)
}
inline std::string* UserFriendRequest::mutable_content() {
  std::string* _s = _internal_mutable_content();
  // @@protoc_insertion_point(field_mutable:turms.client.model.proto.UserFriendRequest.content)
  return _s;
}
inline const std::string& UserFriendRequest::_internal_content() const {
  PROTOBUF_TSAN_READ(&_impl_._tsan_detect_race);
  return _impl_.content_.Get();
}
inline void UserFriendRequest::_internal_set_content(const std::string& value) {
  PROTOBUF_TSAN_WRITE(&_impl_._tsan_detect_race);
  _impl_._has_bits_[0] |= 0x00000001u;
  _impl_.content_.Set(value, GetArenaForAllocation());
}
inline std::string* UserFriendRequest::_internal_mutable_content() {
  PROTOBUF_TSAN_WRITE(&_impl_._tsan_detect_race);
  _impl_._has_bits_[0] |= 0x00000001u;
  return _impl_.content_.Mutable( GetArenaForAllocation());
}
inline std::string* UserFriendRequest::release_content() {
  PROTOBUF_TSAN_WRITE(&_impl_._tsan_detect_race);
  // @@protoc_insertion_point(field_release:turms.client.model.proto.UserFriendRequest.content)
  if ((_impl_._has_bits_[0] & 0x00000001u) == 0) {
    return nullptr;
  }
  _impl_._has_bits_[0] &= ~0x00000001u;
  auto* released = _impl_.content_.Release();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
  _impl_.content_.Set("", GetArenaForAllocation());
  #endif  // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  return released;
}
inline void UserFriendRequest::set_allocated_content(std::string* value) {
  PROTOBUF_TSAN_WRITE(&_impl_._tsan_detect_race);
  if (value != nullptr) {
    _impl_._has_bits_[0] |= 0x00000001u;
  } else {
    _impl_._has_bits_[0] &= ~0x00000001u;
  }
  _impl_.content_.SetAllocated(value, GetArenaForAllocation());
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
        if (_impl_.content_.IsDefault()) {
          _impl_.content_.Set("", GetArenaForAllocation());
        }
  #endif  // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  // @@protoc_insertion_point(field_set_allocated:turms.client.model.proto.UserFriendRequest.content)
}

// optional .turms.client.model.proto.RequestStatus request_status = 4;
inline bool UserFriendRequest::has_request_status() const {
  bool value = (_impl_._has_bits_[0] & 0x00000080u) != 0;
  return value;
}
inline void UserFriendRequest::clear_request_status() {
  _impl_.request_status_ = 0;
  _impl_._has_bits_[0] &= ~0x00000080u;
}
inline ::turms::client::model::proto::RequestStatus UserFriendRequest::request_status() const {
  // @@protoc_insertion_point(field_get:turms.client.model.proto.UserFriendRequest.request_status)
  return _internal_request_status();
}
inline void UserFriendRequest::set_request_status(::turms::client::model::proto::RequestStatus value) {
  _internal_set_request_status(value);
  // @@protoc_insertion_point(field_set:turms.client.model.proto.UserFriendRequest.request_status)
}
inline ::turms::client::model::proto::RequestStatus UserFriendRequest::_internal_request_status() const {
  PROTOBUF_TSAN_READ(&_impl_._tsan_detect_race);
  return static_cast<::turms::client::model::proto::RequestStatus>(_impl_.request_status_);
}
inline void UserFriendRequest::_internal_set_request_status(::turms::client::model::proto::RequestStatus value) {
  PROTOBUF_TSAN_WRITE(&_impl_._tsan_detect_race);
  _impl_._has_bits_[0] |= 0x00000080u;
  _impl_.request_status_ = value;
}

// optional string reason = 5;
inline bool UserFriendRequest::has_reason() const {
  bool value = (_impl_._has_bits_[0] & 0x00000002u) != 0;
  return value;
}
inline void UserFriendRequest::clear_reason() {
  _impl_.reason_.ClearToEmpty();
  _impl_._has_bits_[0] &= ~0x00000002u;
}
inline const std::string& UserFriendRequest::reason() const {
  // @@protoc_insertion_point(field_get:turms.client.model.proto.UserFriendRequest.reason)
  return _internal_reason();
}
template <typename Arg_, typename... Args_>
inline PROTOBUF_ALWAYS_INLINE void UserFriendRequest::set_reason(Arg_&& arg,
                                                     Args_... args) {
  PROTOBUF_TSAN_WRITE(&_impl_._tsan_detect_race);
  _impl_._has_bits_[0] |= 0x00000002u;
  _impl_.reason_.Set(static_cast<Arg_&&>(arg), args..., GetArenaForAllocation());
  // @@protoc_insertion_point(field_set:turms.client.model.proto.UserFriendRequest.reason)
}
inline std::string* UserFriendRequest::mutable_reason() {
  std::string* _s = _internal_mutable_reason();
  // @@protoc_insertion_point(field_mutable:turms.client.model.proto.UserFriendRequest.reason)
  return _s;
}
inline const std::string& UserFriendRequest::_internal_reason() const {
  PROTOBUF_TSAN_READ(&_impl_._tsan_detect_race);
  return _impl_.reason_.Get();
}
inline void UserFriendRequest::_internal_set_reason(const std::string& value) {
  PROTOBUF_TSAN_WRITE(&_impl_._tsan_detect_race);
  _impl_._has_bits_[0] |= 0x00000002u;
  _impl_.reason_.Set(value, GetArenaForAllocation());
}
inline std::string* UserFriendRequest::_internal_mutable_reason() {
  PROTOBUF_TSAN_WRITE(&_impl_._tsan_detect_race);
  _impl_._has_bits_[0] |= 0x00000002u;
  return _impl_.reason_.Mutable( GetArenaForAllocation());
}
inline std::string* UserFriendRequest::release_reason() {
  PROTOBUF_TSAN_WRITE(&_impl_._tsan_detect_race);
  // @@protoc_insertion_point(field_release:turms.client.model.proto.UserFriendRequest.reason)
  if ((_impl_._has_bits_[0] & 0x00000002u) == 0) {
    return nullptr;
  }
  _impl_._has_bits_[0] &= ~0x00000002u;
  auto* released = _impl_.reason_.Release();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
  _impl_.reason_.Set("", GetArenaForAllocation());
  #endif  // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  return released;
}
inline void UserFriendRequest::set_allocated_reason(std::string* value) {
  PROTOBUF_TSAN_WRITE(&_impl_._tsan_detect_race);
  if (value != nullptr) {
    _impl_._has_bits_[0] |= 0x00000002u;
  } else {
    _impl_._has_bits_[0] &= ~0x00000002u;
  }
  _impl_.reason_.SetAllocated(value, GetArenaForAllocation());
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
        if (_impl_.reason_.IsDefault()) {
          _impl_.reason_.Set("", GetArenaForAllocation());
        }
  #endif  // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  // @@protoc_insertion_point(field_set_allocated:turms.client.model.proto.UserFriendRequest.reason)
}

// optional int64 expiration_date = 6;
inline bool UserFriendRequest::has_expiration_date() const {
  bool value = (_impl_._has_bits_[0] & 0x00000010u) != 0;
  return value;
}
inline void UserFriendRequest::clear_expiration_date() {
  _impl_.expiration_date_ = ::int64_t{0};
  _impl_._has_bits_[0] &= ~0x00000010u;
}
inline ::int64_t UserFriendRequest::expiration_date() const {
  // @@protoc_insertion_point(field_get:turms.client.model.proto.UserFriendRequest.expiration_date)
  return _internal_expiration_date();
}
inline void UserFriendRequest::set_expiration_date(::int64_t value) {
  _internal_set_expiration_date(value);
  // @@protoc_insertion_point(field_set:turms.client.model.proto.UserFriendRequest.expiration_date)
}
inline ::int64_t UserFriendRequest::_internal_expiration_date() const {
  PROTOBUF_TSAN_READ(&_impl_._tsan_detect_race);
  return _impl_.expiration_date_;
}
inline void UserFriendRequest::_internal_set_expiration_date(::int64_t value) {
  PROTOBUF_TSAN_WRITE(&_impl_._tsan_detect_race);
  _impl_._has_bits_[0] |= 0x00000010u;
  _impl_.expiration_date_ = value;
}

// optional int64 requester_id = 7;
inline bool UserFriendRequest::has_requester_id() const {
  bool value = (_impl_._has_bits_[0] & 0x00000020u) != 0;
  return value;
}
inline void UserFriendRequest::clear_requester_id() {
  _impl_.requester_id_ = ::int64_t{0};
  _impl_._has_bits_[0] &= ~0x00000020u;
}
inline ::int64_t UserFriendRequest::requester_id() const {
  // @@protoc_insertion_point(field_get:turms.client.model.proto.UserFriendRequest.requester_id)
  return _internal_requester_id();
}
inline void UserFriendRequest::set_requester_id(::int64_t value) {
  _internal_set_requester_id(value);
  // @@protoc_insertion_point(field_set:turms.client.model.proto.UserFriendRequest.requester_id)
}
inline ::int64_t UserFriendRequest::_internal_requester_id() const {
  PROTOBUF_TSAN_READ(&_impl_._tsan_detect_race);
  return _impl_.requester_id_;
}
inline void UserFriendRequest::_internal_set_requester_id(::int64_t value) {
  PROTOBUF_TSAN_WRITE(&_impl_._tsan_detect_race);
  _impl_._has_bits_[0] |= 0x00000020u;
  _impl_.requester_id_ = value;
}

// optional int64 recipient_id = 8;
inline bool UserFriendRequest::has_recipient_id() const {
  bool value = (_impl_._has_bits_[0] & 0x00000040u) != 0;
  return value;
}
inline void UserFriendRequest::clear_recipient_id() {
  _impl_.recipient_id_ = ::int64_t{0};
  _impl_._has_bits_[0] &= ~0x00000040u;
}
inline ::int64_t UserFriendRequest::recipient_id() const {
  // @@protoc_insertion_point(field_get:turms.client.model.proto.UserFriendRequest.recipient_id)
  return _internal_recipient_id();
}
inline void UserFriendRequest::set_recipient_id(::int64_t value) {
  _internal_set_recipient_id(value);
  // @@protoc_insertion_point(field_set:turms.client.model.proto.UserFriendRequest.recipient_id)
}
inline ::int64_t UserFriendRequest::_internal_recipient_id() const {
  PROTOBUF_TSAN_READ(&_impl_._tsan_detect_race);
  return _impl_.recipient_id_;
}
inline void UserFriendRequest::_internal_set_recipient_id(::int64_t value) {
  PROTOBUF_TSAN_WRITE(&_impl_._tsan_detect_race);
  _impl_._has_bits_[0] |= 0x00000040u;
  _impl_.recipient_id_ = value;
}

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif  // __GNUC__

// @@protoc_insertion_point(namespace_scope)
}  // namespace proto
}  // namespace model
}  // namespace client
}  // namespace turms


// @@protoc_insertion_point(global_scope)

#include "google/protobuf/port_undef.inc"

#endif  // GOOGLE_PROTOBUF_INCLUDED_model_2fuser_2fuser_5ffriend_5frequest_2eproto_2epb_2eh