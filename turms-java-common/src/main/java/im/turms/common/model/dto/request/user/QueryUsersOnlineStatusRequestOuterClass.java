// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: request/user/query_users_online_status_request.proto

package im.turms.common.model.dto.request.user;

public final class QueryUsersOnlineStatusRequestOuterClass {
  private QueryUsersOnlineStatusRequestOuterClass() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_im_turms_proto_QueryUsersOnlineStatusRequest_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_im_turms_proto_QueryUsersOnlineStatusRequest_fieldAccessorTable;

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n4request/user/query_users_online_status" +
      "_request.proto\022\016im.turms.proto\"2\n\035QueryU" +
      "sersOnlineStatusRequest\022\021\n\tusers_ids\030\001 \003" +
      "(\003B-\n&im.turms.common.model.dto.request." +
      "userP\001\272\002\000b\006proto3"
    };
    descriptor = com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
        });
    internal_static_im_turms_proto_QueryUsersOnlineStatusRequest_descriptor =
      getDescriptor().getMessageTypes().get(0);
    internal_static_im_turms_proto_QueryUsersOnlineStatusRequest_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_im_turms_proto_QueryUsersOnlineStatusRequest_descriptor,
        new java.lang.String[] { "UsersIds", });
  }

  // @@protoc_insertion_point(outer_class_scope)
}