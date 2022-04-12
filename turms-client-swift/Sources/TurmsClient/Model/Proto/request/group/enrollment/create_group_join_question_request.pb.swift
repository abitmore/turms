// DO NOT EDIT.
// swift-format-ignore-file
//
// Generated by the Swift generator plugin for the protocol buffer compiler.
// Source: request/group/enrollment/create_group_join_question_request.proto
//
// For information on using the generated types, please see the documentation:
//   https://github.com/apple/swift-protobuf/

import Foundation
import SwiftProtobuf

// If the compiler emits an error on this type, it is because this file
// was generated by a version of the `protoc` Swift plug-in that is
// incompatible with the version of SwiftProtobuf to which you are linking.
// Please ensure that you are building against the same version of the API
// that was used to generate this file.
private struct _GeneratedWithProtocGenSwiftVersion: SwiftProtobuf.ProtobufAPIVersionCheck {
    struct _2: SwiftProtobuf.ProtobufAPIVersion_2 {}
    typealias Version = _2
}

public struct CreateGroupJoinQuestionRequest {
    // SwiftProtobuf.Message conformance is added in an extension below. See the
    // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
    // methods supported on all messages.

    public var groupID: Int64 = 0

    public var question: String = .init()

    public var answers: [String] = []

    public var score: Int32 = 0

    public var unknownFields = SwiftProtobuf.UnknownStorage()

    public init() {}
}

// MARK: - Code below here is support for the SwiftProtobuf runtime.

private let _protobuf_package = "im.turms.proto"

extension CreateGroupJoinQuestionRequest: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
    public static let protoMessageName: String = _protobuf_package + ".CreateGroupJoinQuestionRequest"
    public static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
        1: .standard(proto: "group_id"),
        2: .same(proto: "question"),
        3: .same(proto: "answers"),
        4: .same(proto: "score"),
    ]

    public mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
        while let fieldNumber = try decoder.nextFieldNumber() {
            // The use of inline closures is to circumvent an issue where the compiler
            // allocates stack space for every case branch when no optimizations are
            // enabled. https://github.com/apple/swift-protobuf/issues/1034
            switch fieldNumber {
            case 1: try try decoder.decodeSingularInt64Field(value: &groupID)
            case 2: try try decoder.decodeSingularStringField(value: &question)
            case 3: try try decoder.decodeRepeatedStringField(value: &answers)
            case 4: try try decoder.decodeSingularInt32Field(value: &score)
            default: break
            }
        }
    }

    public func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
        if groupID != 0 {
            try visitor.visitSingularInt64Field(value: groupID, fieldNumber: 1)
        }
        if !question.isEmpty {
            try visitor.visitSingularStringField(value: question, fieldNumber: 2)
        }
        if !answers.isEmpty {
            try visitor.visitRepeatedStringField(value: answers, fieldNumber: 3)
        }
        if score != 0 {
            try visitor.visitSingularInt32Field(value: score, fieldNumber: 4)
        }
        try unknownFields.traverse(visitor: &visitor)
    }

    public static func == (lhs: CreateGroupJoinQuestionRequest, rhs: CreateGroupJoinQuestionRequest) -> Bool {
        if lhs.groupID != rhs.groupID { return false }
        if lhs.question != rhs.question { return false }
        if lhs.answers != rhs.answers { return false }
        if lhs.score != rhs.score { return false }
        if lhs.unknownFields != rhs.unknownFields { return false }
        return true
    }
}