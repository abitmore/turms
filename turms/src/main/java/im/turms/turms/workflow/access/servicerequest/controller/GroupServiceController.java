/*
 * Copyright (C) 2019 The Turms Project
 * https://github.com/turms-im/turms
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package im.turms.turms.workflow.access.servicerequest.controller;

import im.turms.common.constant.GroupMemberRole;
import im.turms.common.model.dto.notification.TurmsNotification;
import im.turms.common.model.dto.request.group.CreateGroupRequest;
import im.turms.common.model.dto.request.group.DeleteGroupRequest;
import im.turms.common.model.dto.request.group.QueryGroupRequest;
import im.turms.common.model.dto.request.group.QueryJoinedGroupIdsRequest;
import im.turms.common.model.dto.request.group.QueryJoinedGroupInfosRequest;
import im.turms.common.model.dto.request.group.UpdateGroupRequest;
import im.turms.common.model.dto.request.group.blocklist.CreateGroupBlockedUserRequest;
import im.turms.common.model.dto.request.group.blocklist.DeleteGroupBlockedUserRequest;
import im.turms.common.model.dto.request.group.blocklist.QueryGroupBlockedUserIdsRequest;
import im.turms.common.model.dto.request.group.blocklist.QueryGroupBlockedUserInfosRequest;
import im.turms.common.model.dto.request.group.enrollment.CheckGroupJoinQuestionsAnswersRequest;
import im.turms.common.model.dto.request.group.enrollment.CreateGroupInvitationRequest;
import im.turms.common.model.dto.request.group.enrollment.CreateGroupJoinQuestionRequest;
import im.turms.common.model.dto.request.group.enrollment.CreateGroupJoinRequestRequest;
import im.turms.common.model.dto.request.group.enrollment.DeleteGroupInvitationRequest;
import im.turms.common.model.dto.request.group.enrollment.DeleteGroupJoinQuestionRequest;
import im.turms.common.model.dto.request.group.enrollment.DeleteGroupJoinRequestRequest;
import im.turms.common.model.dto.request.group.enrollment.QueryGroupInvitationsRequest;
import im.turms.common.model.dto.request.group.enrollment.QueryGroupJoinQuestionsRequest;
import im.turms.common.model.dto.request.group.enrollment.QueryGroupJoinRequestsRequest;
import im.turms.common.model.dto.request.group.enrollment.UpdateGroupJoinQuestionRequest;
import im.turms.common.model.dto.request.group.member.CreateGroupMemberRequest;
import im.turms.common.model.dto.request.group.member.DeleteGroupMemberRequest;
import im.turms.common.model.dto.request.group.member.QueryGroupMembersRequest;
import im.turms.common.model.dto.request.group.member.UpdateGroupMemberRequest;
import im.turms.server.common.cluster.node.Node;
import im.turms.server.common.constant.TurmsStatusCode;
import im.turms.server.common.util.CollectionUtil;
import im.turms.turms.bo.GroupQuestionIdAndAnswer;
import im.turms.turms.workflow.access.servicerequest.dispatcher.ClientRequestHandler;
import im.turms.turms.workflow.access.servicerequest.dispatcher.ServiceRequestMapping;
import im.turms.turms.workflow.access.servicerequest.dto.RequestHandlerResultFactory;
import im.turms.turms.workflow.service.impl.group.GroupBlocklistService;
import im.turms.turms.workflow.service.impl.group.GroupInvitationService;
import im.turms.turms.workflow.service.impl.group.GroupJoinRequestService;
import im.turms.turms.workflow.service.impl.group.GroupMemberService;
import im.turms.turms.workflow.service.impl.group.GroupQuestionService;
import im.turms.turms.workflow.service.impl.group.GroupService;
import org.springframework.stereotype.Controller;
import reactor.core.publisher.Mono;

import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static im.turms.common.model.dto.request.TurmsRequest.KindCase.CHECK_GROUP_JOIN_QUESTIONS_ANSWERS_REQUEST;
import static im.turms.common.model.dto.request.TurmsRequest.KindCase.CREATE_GROUP_BLOCKED_USER_REQUEST;
import static im.turms.common.model.dto.request.TurmsRequest.KindCase.CREATE_GROUP_INVITATION_REQUEST;
import static im.turms.common.model.dto.request.TurmsRequest.KindCase.CREATE_GROUP_JOIN_QUESTION_REQUEST;
import static im.turms.common.model.dto.request.TurmsRequest.KindCase.CREATE_GROUP_JOIN_REQUEST_REQUEST;
import static im.turms.common.model.dto.request.TurmsRequest.KindCase.CREATE_GROUP_MEMBER_REQUEST;
import static im.turms.common.model.dto.request.TurmsRequest.KindCase.CREATE_GROUP_REQUEST;
import static im.turms.common.model.dto.request.TurmsRequest.KindCase.DELETE_GROUP_BLOCKED_USER_REQUEST;
import static im.turms.common.model.dto.request.TurmsRequest.KindCase.DELETE_GROUP_INVITATION_REQUEST;
import static im.turms.common.model.dto.request.TurmsRequest.KindCase.DELETE_GROUP_JOIN_QUESTION_REQUEST;
import static im.turms.common.model.dto.request.TurmsRequest.KindCase.DELETE_GROUP_JOIN_REQUEST_REQUEST;
import static im.turms.common.model.dto.request.TurmsRequest.KindCase.DELETE_GROUP_MEMBER_REQUEST;
import static im.turms.common.model.dto.request.TurmsRequest.KindCase.DELETE_GROUP_REQUEST;
import static im.turms.common.model.dto.request.TurmsRequest.KindCase.QUERY_GROUP_BLOCKED_USER_IDS_REQUEST;
import static im.turms.common.model.dto.request.TurmsRequest.KindCase.QUERY_GROUP_BLOCKED_USER_INFOS_REQUEST;
import static im.turms.common.model.dto.request.TurmsRequest.KindCase.QUERY_GROUP_INVITATIONS_REQUEST;
import static im.turms.common.model.dto.request.TurmsRequest.KindCase.QUERY_GROUP_JOIN_QUESTIONS_REQUEST;
import static im.turms.common.model.dto.request.TurmsRequest.KindCase.QUERY_GROUP_JOIN_REQUESTS_REQUEST;
import static im.turms.common.model.dto.request.TurmsRequest.KindCase.QUERY_GROUP_MEMBERS_REQUEST;
import static im.turms.common.model.dto.request.TurmsRequest.KindCase.QUERY_GROUP_REQUEST;
import static im.turms.common.model.dto.request.TurmsRequest.KindCase.QUERY_JOINED_GROUP_IDS_REQUEST;
import static im.turms.common.model.dto.request.TurmsRequest.KindCase.QUERY_JOINED_GROUP_INFOS_REQUEST;
import static im.turms.common.model.dto.request.TurmsRequest.KindCase.UPDATE_GROUP_JOIN_QUESTION_REQUEST;
import static im.turms.common.model.dto.request.TurmsRequest.KindCase.UPDATE_GROUP_MEMBER_REQUEST;
import static im.turms.common.model.dto.request.TurmsRequest.KindCase.UPDATE_GROUP_REQUEST;

/**
 * @author James Chen
 */
@Controller
public class GroupServiceController {

    private final Node node;
    private final GroupService groupService;
    private final GroupBlocklistService groupBlocklistService;
    private final GroupQuestionService groupQuestionService;
    private final GroupInvitationService groupInvitationService;
    private final GroupJoinRequestService groupJoinRequestService;
    private final GroupMemberService groupMemberService;

    public GroupServiceController(
            Node node,
            GroupService groupService,
            GroupBlocklistService groupBlocklistService,
            GroupQuestionService groupQuestionService,
            GroupInvitationService groupInvitationService,
            GroupJoinRequestService groupJoinRequestService,
            GroupMemberService groupMemberService) {
        this.node = node;
        this.groupService = groupService;
        this.groupBlocklistService = groupBlocklistService;
        this.groupQuestionService = groupQuestionService;
        this.groupInvitationService = groupInvitationService;
        this.groupJoinRequestService = groupJoinRequestService;
        this.groupMemberService = groupMemberService;
    }

    @ServiceRequestMapping(CREATE_GROUP_REQUEST)
    public ClientRequestHandler handleCreateGroupRequest() {
        return clientRequest -> {
            CreateGroupRequest request = clientRequest.getTurmsRequest().getCreateGroupRequest();
            String intro = request.hasIntro() ? request.getIntro() : null;
            String announcement = request.hasAnnouncement() ? request.getAnnouncement() : null;
            Integer minimumScore = request.hasMinimumScore() ? request.getMinimumScore() : null;
            Long groupTypeId = request.hasGroupTypeId() ? request.getGroupTypeId() : null;
            Date muteEndDate = request.hasMuteEndDate() ? new Date(request.getMuteEndDate()) : null;
            Long creatorIdAndOwnerId = clientRequest.getUserId();
            return groupService.authAndCreateGroup(
                            creatorIdAndOwnerId,
                            creatorIdAndOwnerId,
                            request.getName(),
                            intro,
                            announcement,
                            minimumScore,
                            groupTypeId,
                            muteEndDate,
                            null,
                            null,
                            node.getSharedProperties().getService().getGroup().isActivateGroupWhenCreated())
                    .map(group -> RequestHandlerResultFactory.get(group.getId()));
        };
    }

    @ServiceRequestMapping(DELETE_GROUP_REQUEST)
    public ClientRequestHandler handleDeleteGroupRequest() {
        return clientRequest -> {
            DeleteGroupRequest request = clientRequest.getTurmsRequest().getDeleteGroupRequest();
            return groupService.authAndDeleteGroup(clientRequest.getUserId(), request.getGroupId())
                    .then(Mono.defer(() -> {
                        if (node.getSharedProperties().getService().getNotification().isNotifyMembersAfterGroupDeleted()) {
                            return groupService.queryGroupMemberIds(request.getGroupId())
                                    .collect(Collectors.toSet())
                                    .map(memberIds -> memberIds.isEmpty()
                                            ? RequestHandlerResultFactory.OK
                                            : RequestHandlerResultFactory.get(memberIds, clientRequest.getTurmsRequest()));
                        } else {
                            return Mono.just(RequestHandlerResultFactory.OK);
                        }
                    }));
        };
    }

    @ServiceRequestMapping(QUERY_GROUP_REQUEST)
    public ClientRequestHandler handleQueryGroupRequest() {
        return clientRequest -> {
            QueryGroupRequest request = clientRequest.getTurmsRequest().getQueryGroupRequest();
            Date lastUpdatedDate = request.hasLastUpdatedDate()
                    ? new Date(request.getLastUpdatedDate())
                    : null;
            return groupService.queryGroupWithVersion(request.getGroupId(), lastUpdatedDate)
                    .map(groupsWithVersion -> RequestHandlerResultFactory.get(TurmsNotification.Data.newBuilder()
                            .setGroupsWithVersion(groupsWithVersion)
                            .build()));
        };
    }

    @ServiceRequestMapping(QUERY_JOINED_GROUP_IDS_REQUEST)
    public ClientRequestHandler handleQueryJoinedGroupIdsRequest() {
        return clientRequest -> {
            QueryJoinedGroupIdsRequest request = clientRequest.getTurmsRequest()
                    .getQueryJoinedGroupIdsRequest();
            Date lastUpdatedDate = request.hasLastUpdatedDate() ? new Date(request.getLastUpdatedDate()) : null;
            return groupService.queryJoinedGroupIdsWithVersion(
                            clientRequest.getUserId(),
                            lastUpdatedDate)
                    .map(idsWithVersion -> RequestHandlerResultFactory.get(TurmsNotification.Data
                            .newBuilder()
                            .setIdsWithVersion(idsWithVersion)
                            .build()));
        };
    }

    @ServiceRequestMapping(QUERY_JOINED_GROUP_INFOS_REQUEST)
    public ClientRequestHandler handleQueryJoinedGroupsRequest() {
        return clientRequest -> {
            QueryJoinedGroupInfosRequest request = clientRequest.getTurmsRequest()
                    .getQueryJoinedGroupInfosRequest();
            Date lastUpdatedDate = request.hasLastUpdatedDate() ? new Date(request.getLastUpdatedDate()) : null;
            return groupService.queryJoinedGroupsWithVersion(
                            clientRequest.getUserId(),
                            lastUpdatedDate)
                    .map(groupsWithVersion -> RequestHandlerResultFactory.get(TurmsNotification.Data
                            .newBuilder()
                            .setGroupsWithVersion(groupsWithVersion)
                            .build()));
        };
    }

    @ServiceRequestMapping(UPDATE_GROUP_REQUEST)
    public ClientRequestHandler handleUpdateGroupRequest() {
        return clientRequest -> {
            UpdateGroupRequest request = clientRequest.getTurmsRequest().getUpdateGroupRequest();
            Long successorId = request.hasSuccessorId() ? request.getSuccessorId() : null;
            Mono<Void> updateMono;
            if (successorId != null) {
                boolean quitAfterTransfer = request.hasQuitAfterTransfer() && request.getQuitAfterTransfer();
                updateMono = groupService
                        .authAndTransferGroupOwnership(clientRequest.getUserId(), request.getGroupId(), successorId, quitAfterTransfer,
                                null);
            } else {
                Integer minimumScore = request.hasMinimumScore() ? request.getMinimumScore() : null;
                Long groupTypeId = request.hasGroupTypeId() ? request.getGroupTypeId() : null;
                String groupName = request.hasGroupName() ? request.getGroupName() : null;
                String intro = request.hasIntro() ? request.getIntro() : null;
                String announcement = request.hasAnnouncement() ? request.getAnnouncement() : null;
                Date muteEndDate = request.hasMuteEndDate() ? new Date(request.getMuteEndDate()) : null;
                updateMono = groupService.authAndUpdateGroupInformation(
                        clientRequest.getUserId(),
                        request.getGroupId(),
                        groupTypeId,
                        null,
                        null,
                        groupName,
                        intro,
                        announcement,
                        minimumScore,
                        null,
                        null,
                        null,
                        muteEndDate,
                        null);
            }
            return updateMono.then(Mono.defer(() -> {
                if (node.getSharedProperties().getService().getNotification().isNotifyMembersAfterGroupUpdated()) {
                    return groupMemberService.queryGroupMemberIds(request.getGroupId())
                            .collect(Collectors.toSet())
                            .map(memberIds -> memberIds.isEmpty()
                                    ? RequestHandlerResultFactory.OK
                                    : RequestHandlerResultFactory.get(memberIds, clientRequest.getTurmsRequest()));
                } else {
                    return Mono.just(RequestHandlerResultFactory.OK);
                }
            }));
        };
    }

    @ServiceRequestMapping(CREATE_GROUP_BLOCKED_USER_REQUEST)
    public ClientRequestHandler handleCreateGroupBlockedUserRequest() {
        return clientRequest -> {
            CreateGroupBlockedUserRequest request = clientRequest.getTurmsRequest()
                    .getCreateGroupBlockedUserRequest();
            return groupBlocklistService.blockUser(
                            clientRequest.getUserId(),
                            request.getGroupId(),
                            request.getUserId(),
                            null)
                    .then(Mono
                            .fromCallable(() -> node.getSharedProperties().getService().getNotification().isNotifyUserAfterBlockedByGroup()
                                    ? RequestHandlerResultFactory.get(request.getUserId(), clientRequest.getTurmsRequest())
                                    : RequestHandlerResultFactory.OK));
        };
    }

    @ServiceRequestMapping(DELETE_GROUP_BLOCKED_USER_REQUEST)
    public ClientRequestHandler handleDeleteGroupBlockedUserRequest() {
        return clientRequest -> {
            DeleteGroupBlockedUserRequest request = clientRequest.getTurmsRequest()
                    .getDeleteGroupBlockedUserRequest();
            return groupBlocklistService.unblockUser(
                            clientRequest.getUserId(),
                            request.getGroupId(),
                            request.getUserId(),
                            null,
                            true)
                    .then(Mono.fromCallable(
                            () -> node.getSharedProperties().getService().getNotification().isNotifyUserAfterUnblockedByGroup()
                                    ? RequestHandlerResultFactory.get(request.getUserId(), clientRequest.getTurmsRequest())
                                    : RequestHandlerResultFactory.OK));
        };
    }

    @ServiceRequestMapping(QUERY_GROUP_BLOCKED_USER_IDS_REQUEST)
    public ClientRequestHandler handleQueryGroupBlockedUserIdsRequest() {
        return clientRequest -> {
            QueryGroupBlockedUserIdsRequest request = clientRequest.getTurmsRequest()
                    .getQueryGroupBlockedUserIdsRequest();
            Date lastUpdatedDate = request.hasLastUpdatedDate() ?
                    new Date(request.getLastUpdatedDate()) : null;
            return groupBlocklistService.queryGroupBlockedUserIdsWithVersion(
                            request.getGroupId(),
                            lastUpdatedDate)
                    .map(version -> RequestHandlerResultFactory.get(TurmsNotification.Data
                            .newBuilder()
                            .setIdsWithVersion(version)
                            .build()));
        };
    }

    @ServiceRequestMapping(QUERY_GROUP_BLOCKED_USER_INFOS_REQUEST)
    public ClientRequestHandler handleQueryGroupBlockedUsersInfosRequest() {
        return clientRequest -> {
            QueryGroupBlockedUserInfosRequest request = clientRequest.getTurmsRequest()
                    .getQueryGroupBlockedUserInfosRequest();
            Date lastUpdatedDate = request.hasLastUpdatedDate() ? new Date(request.getLastUpdatedDate()) : null;
            return groupBlocklistService.queryGroupBlockedUserInfosWithVersion(
                            request.getGroupId(),
                            lastUpdatedDate)
                    .map(version -> RequestHandlerResultFactory.get(TurmsNotification.Data
                            .newBuilder()
                            .setUsersInfosWithVersion(version)
                            .build()));
        };
    }

    @ServiceRequestMapping(CHECK_GROUP_JOIN_QUESTIONS_ANSWERS_REQUEST)
    public ClientRequestHandler handleCheckGroupQuestionAnswerRequest() {
        return clientRequest -> {
            CheckGroupJoinQuestionsAnswersRequest request = clientRequest.getTurmsRequest()
                    .getCheckGroupJoinQuestionsAnswersRequest();
            Set<GroupQuestionIdAndAnswer> idAndAnswers =
                    CollectionUtil.newSetWithExpectedSize(request.getQuestionIdAndAnswerCount());
            for (Map.Entry<Long, String> entry : request.getQuestionIdAndAnswerMap().entrySet()) {
                idAndAnswers.add(new GroupQuestionIdAndAnswer(entry.getKey(), entry.getValue()));
            }
            return groupQuestionService.checkGroupQuestionAnswerAndJoin(clientRequest.getUserId(), idAndAnswers)
                    .map(answerResult -> RequestHandlerResultFactory.get(TurmsNotification.Data.newBuilder()
                            .setGroupJoinQuestionAnswerResult(answerResult).build()));
        };
    }

    @ServiceRequestMapping(CREATE_GROUP_INVITATION_REQUEST)
    public ClientRequestHandler handleCreateGroupInvitationRequestRequest() {
        return clientRequest -> {
            CreateGroupInvitationRequest request = clientRequest.getTurmsRequest()
                    .getCreateGroupInvitationRequest();
            return groupInvitationService.authAndCreateGroupInvitation(
                            request.getGroupId(),
                            clientRequest.getUserId(),
                            request.getInviteeId(),
                            request.getContent())
                    .map(invitation -> node.getSharedProperties().getService().getNotification().isNotifyUserAfterInvitedByGroup()
                            ? RequestHandlerResultFactory.get(invitation.getId(), request.getInviteeId(), clientRequest.getTurmsRequest())
                            : RequestHandlerResultFactory.OK);
        };
    }

    @ServiceRequestMapping(CREATE_GROUP_JOIN_REQUEST_REQUEST)
    public ClientRequestHandler handleCreateGroupJoinRequestRequest() {
        return clientRequest -> {
            CreateGroupJoinRequestRequest request = clientRequest.getTurmsRequest()
                    .getCreateGroupJoinRequestRequest();
            return groupJoinRequestService.authAndCreateGroupJoinRequest(
                            clientRequest.getUserId(),
                            request.getGroupId(),
                            request.getContent())
                    .flatMap(joinRequest -> {
                        if (node.getSharedProperties().getService().getNotification().isNotifyOwnerAndManagersAfterReceivingJoinRequest()) {
                            return groupMemberService.queryGroupManagersAndOwnerId(request.getGroupId())
                                    .collect(Collectors.toSet())
                                    .map(recipientsIds -> recipientsIds.isEmpty()
                                            ? RequestHandlerResultFactory.OK
                                            : RequestHandlerResultFactory
                                            .get(joinRequest.getId(), recipientsIds, false, clientRequest.getTurmsRequest()));
                        } else {
                            return Mono.just(RequestHandlerResultFactory.OK);
                        }
                    });
        };
    }

    @ServiceRequestMapping(CREATE_GROUP_JOIN_QUESTION_REQUEST)
    public ClientRequestHandler handleCreateGroupQuestionRequest() {
        return clientRequest -> {
            CreateGroupJoinQuestionRequest request = clientRequest.getTurmsRequest()
                    .getCreateGroupJoinQuestionRequest();
            if (request.getAnswersCount() == 0) {
                return Mono.just(RequestHandlerResultFactory.get(TurmsStatusCode.ILLEGAL_ARGUMENT, "The answers must not be empty"));
            } else {
                Set<String> answers = CollectionUtil.newSet(request.getAnswersList());
                int score = request.getScore();
                return score >= 0
                        ? groupQuestionService
                        .authAndCreateGroupJoinQuestion(clientRequest.getUserId(), request.getGroupId(), request.getQuestion(), answers,
                                score)
                        .map(question -> RequestHandlerResultFactory.get(question.getId()))
                        : Mono.just(
                        RequestHandlerResultFactory.get(TurmsStatusCode.ILLEGAL_ARGUMENT, "The score must be greater than or equal to 0"));
            }
        };
    }

    @ServiceRequestMapping(DELETE_GROUP_INVITATION_REQUEST)
    public ClientRequestHandler handleDeleteGroupInvitationRequest() {
        return clientRequest -> {
            DeleteGroupInvitationRequest request = clientRequest.getTurmsRequest().getDeleteGroupInvitationRequest();
            return groupInvitationService.queryInviteeIdByInvitationId(request.getInvitationId())
                    .flatMap(inviteeId -> groupInvitationService.recallPendingGroupInvitation(
                                    clientRequest.getUserId(),
                                    request.getInvitationId())
                            .then(Mono.fromCallable(() -> node.getSharedProperties().getService().getNotification()
                                    .isNotifyInviteeAfterGroupInvitationRecalled()
                                    ? RequestHandlerResultFactory.get(inviteeId, clientRequest.getTurmsRequest())
                                    : RequestHandlerResultFactory.OK)));
        };
    }

    @ServiceRequestMapping(DELETE_GROUP_JOIN_REQUEST_REQUEST)
    public ClientRequestHandler handleDeleteGroupJoinRequestRequest() {
        return clientRequest -> {
            DeleteGroupJoinRequestRequest request = clientRequest.getTurmsRequest()
                    .getDeleteGroupJoinRequestRequest();
            return groupJoinRequestService.recallPendingGroupJoinRequest(
                            clientRequest.getUserId(),
                            request.getRequestId())
                    .then(Mono.defer(() -> {
                        if (node.getSharedProperties().getService().getNotification()
                                .isNotifyOwnerAndManagersAfterGroupJoinRequestRecalled()) {
                            return groupJoinRequestService.queryGroupId(request.getRequestId())
                                    .flatMap(groupId -> groupMemberService.queryGroupManagersAndOwnerId(groupId)
                                            .collect(Collectors.toSet())
                                            .map(ids -> ids.isEmpty()
                                                    ? RequestHandlerResultFactory.OK
                                                    : RequestHandlerResultFactory.get(ids, clientRequest.getTurmsRequest())));
                        } else {
                            return Mono.just(RequestHandlerResultFactory.OK);
                        }
                    }));
        };
    }

    @ServiceRequestMapping(DELETE_GROUP_JOIN_QUESTION_REQUEST)
    public ClientRequestHandler handleDeleteGroupJoinQuestionRequest() {
        return clientRequest -> {
            DeleteGroupJoinQuestionRequest request = clientRequest.getTurmsRequest()
                    .getDeleteGroupJoinQuestionRequest();
            return groupQuestionService.authAndDeleteGroupJoinQuestion(
                            clientRequest.getUserId(),
                            request.getQuestionId())
                    .thenReturn(RequestHandlerResultFactory.OK);
        };
    }

    @ServiceRequestMapping(QUERY_GROUP_INVITATIONS_REQUEST)
    public ClientRequestHandler handleQueryGroupInvitationsRequest() {
        return clientRequest -> {
            QueryGroupInvitationsRequest request = clientRequest.getTurmsRequest()
                    .getQueryGroupInvitationsRequest();
            Long groupId = request.hasGroupId() ? request.getGroupId() : null;
            Date lastUpdatedDate = request.hasLastUpdatedDate() ? new Date(request.getLastUpdatedDate()) : null;
            if (groupId != null) {
                return groupInvitationService.queryGroupInvitationsWithVersion(
                                clientRequest.getUserId(),
                                groupId,
                                lastUpdatedDate)
                        .map(groupInvitationsWithVersion -> RequestHandlerResultFactory.get(
                                TurmsNotification.Data.newBuilder()
                                        .setGroupInvitationsWithVersion(groupInvitationsWithVersion)
                                        .build()));
            } else {
                return groupInvitationService.queryUserGroupInvitationsWithVersion(
                                clientRequest.getUserId(),
                                request.hasAreSentByMe() && request.getAreSentByMe(),
                                lastUpdatedDate)
                        .map(groupInvitationsWithVersion -> RequestHandlerResultFactory.get(TurmsNotification.Data
                                .newBuilder()
                                .setGroupInvitationsWithVersion(groupInvitationsWithVersion)
                                .build()));
            }
        };
    }

    @ServiceRequestMapping(QUERY_GROUP_JOIN_REQUESTS_REQUEST)
    public ClientRequestHandler handleQueryGroupJoinRequestsRequest() {
        return clientRequest -> {
            QueryGroupJoinRequestsRequest request = clientRequest.getTurmsRequest()
                    .getQueryGroupJoinRequestsRequest();
            Long groupId = request.hasGroupId() ? request.getGroupId() : null;
            Date lastUpdatedDate = request.hasLastUpdatedDate() ? new Date(request.getLastUpdatedDate()) : null;
            return groupJoinRequestService.queryGroupJoinRequestsWithVersion(
                            clientRequest.getUserId(),
                            groupId,
                            lastUpdatedDate)
                    .map(groupJoinRequestsWithVersion -> RequestHandlerResultFactory.get(TurmsNotification.Data.newBuilder()
                            .setGroupJoinRequestsWithVersion(groupJoinRequestsWithVersion)
                            .build()));
        };
    }

    @ServiceRequestMapping(QUERY_GROUP_JOIN_QUESTIONS_REQUEST)
    public ClientRequestHandler handleQueryGroupJoinQuestionsRequest() {
        return clientRequest -> {
            QueryGroupJoinQuestionsRequest request = clientRequest.getTurmsRequest()
                    .getQueryGroupJoinQuestionsRequest();
            Date lastUpdatedDate = request.hasLastUpdatedDate() ? new Date(request.getLastUpdatedDate()) : null;
            return groupQuestionService.queryGroupJoinQuestionsWithVersion(
                            clientRequest.getUserId(),
                            request.getGroupId(),
                            request.getWithAnswers(),
                            lastUpdatedDate)
                    .map(groupJoinQuestionsWithVersion -> RequestHandlerResultFactory.get(TurmsNotification.Data.newBuilder()
                            .setGroupJoinQuestionsWithVersion(groupJoinQuestionsWithVersion)
                            .build()));
        };
    }

    @ServiceRequestMapping(UPDATE_GROUP_JOIN_QUESTION_REQUEST)
    public ClientRequestHandler handleUpdateGroupJoinQuestionRequest() {
        return clientRequest -> {
            UpdateGroupJoinQuestionRequest request = clientRequest.getTurmsRequest()
                    .getUpdateGroupJoinQuestionRequest();
            Set<String> answers = request.getAnswersList().isEmpty() ?
                    null : CollectionUtil.newSet(request.getAnswersList());
            String question = request.hasQuestion() ? request.getQuestion() : null;
            Integer score = request.hasScore() ? request.getScore() : null;
            return groupQuestionService.authAndUpdateGroupJoinQuestion(
                            clientRequest.getUserId(),
                            request.getQuestionId(),
                            question,
                            answers,
                            score)
                    .thenReturn(RequestHandlerResultFactory.OK);
        };
    }

    @ServiceRequestMapping(CREATE_GROUP_MEMBER_REQUEST)
    public ClientRequestHandler handleCreateGroupMemberRequest() {
        return clientRequest -> {
            CreateGroupMemberRequest request = clientRequest.getTurmsRequest().getCreateGroupMemberRequest();
            String name = request.hasName() ? request.getName() : null;
            Date muteEndDate = request.hasMuteEndDate() ? new Date(request.getMuteEndDate()) : null;
            GroupMemberRole role = request.getRole();
            if (role == GroupMemberRole.UNRECOGNIZED) {
                role = GroupMemberRole.MEMBER;
            } else if (role == GroupMemberRole.OWNER) {
                return Mono.just(RequestHandlerResultFactory
                        .get(TurmsStatusCode.ILLEGAL_ARGUMENT, "The role of the new member must not be OWNER"));
            }
            return groupMemberService.authAndAddGroupMember(
                            clientRequest.getUserId(),
                            request.getGroupId(),
                            request.getUserId(),
                            role,
                            name,
                            muteEndDate,
                            null)
                    .map(member -> member != null &&
                            node.getSharedProperties().getService().getNotification().isNotifyUserAfterAddedToGroupByOthers()
                            ? RequestHandlerResultFactory.get(request.getUserId(), clientRequest.getTurmsRequest())
                            : RequestHandlerResultFactory.OK);
        };
    }

    @ServiceRequestMapping(DELETE_GROUP_MEMBER_REQUEST)
    public ClientRequestHandler handleDeleteGroupMemberRequest() {
        return clientRequest -> {
            DeleteGroupMemberRequest request = clientRequest.getTurmsRequest().getDeleteGroupMemberRequest();
            Long successorId = request.hasSuccessorId() ? request.getSuccessorId() : null;
            Boolean quitAfterTransfer = request.hasQuitAfterTransfer() ? request.getQuitAfterTransfer() : null;
            return groupMemberService.authAndDeleteGroupMember(
                            clientRequest.getUserId(),
                            request.getGroupId(),
                            request.getMemberId(),
                            successorId,
                            quitAfterTransfer)
                    .then(Mono.fromCallable(
                            () -> node.getSharedProperties().getService().getNotification().isNotifyUserAfterRemovedFromGroupByOthers()
                                    && !clientRequest.getUserId().equals(request.getMemberId())
                                    ? RequestHandlerResultFactory.get(request.getMemberId(), clientRequest.getTurmsRequest())
                                    : RequestHandlerResultFactory.OK));
        };
    }

    @ServiceRequestMapping(QUERY_GROUP_MEMBERS_REQUEST)
    public ClientRequestHandler handleQueryGroupMembersRequest() {
        return clientRequest -> {
            QueryGroupMembersRequest request = clientRequest.getTurmsRequest().getQueryGroupMembersRequest();
            Date lastUpdatedDate = request.hasLastUpdatedDate() ? new Date(request.getLastUpdatedDate()) : null;
            Set<Long> memberIds = request.getMemberIdsCount() != 0 ?
                    CollectionUtil.newSet(request.getMemberIdsList()) : null;
            boolean withStatus = request.hasWithStatus() && request.getWithStatus();
            if (request.getMemberIdsCount() > 0) {
                return groupMemberService.authAndQueryGroupMembers(
                                clientRequest.getUserId(),
                                request.getGroupId(),
                                memberIds,
                                withStatus)
                        .map(groupMembersWithVersion -> RequestHandlerResultFactory.get(
                                TurmsNotification.Data.newBuilder()
                                        .setGroupMembersWithVersion(groupMembersWithVersion)
                                        .build()));
            } else {
                return groupMemberService.authAndQueryGroupMembersWithVersion(
                                clientRequest.getUserId(),
                                request.getGroupId(),
                                lastUpdatedDate,
                                withStatus)
                        .map(groupMembersWithVersion -> RequestHandlerResultFactory.get(
                                TurmsNotification.Data.newBuilder()
                                        .setGroupMembersWithVersion(groupMembersWithVersion)
                                        .build()));
            }
        };
    }

    @ServiceRequestMapping(UPDATE_GROUP_MEMBER_REQUEST)
    public ClientRequestHandler handleUpdateGroupMemberRequest() {
        return clientRequest -> {
            UpdateGroupMemberRequest request = clientRequest.getTurmsRequest().getUpdateGroupMemberRequest();
            String name = request.hasName() ? request.getName() : null;
            GroupMemberRole role = request.getRole() != GroupMemberRole.UNRECOGNIZED ? request.getRole() : null;
            Date muteEndDate = request.hasMuteEndDate() ? new Date(request.getMuteEndDate()) : null;
            return groupMemberService.authAndUpdateGroupMember(
                            clientRequest.getUserId(),
                            request.getGroupId(),
                            request.getMemberId(),
                            name,
                            role,
                            muteEndDate)
                    .then(Mono.defer(() -> {
                        if (node.getSharedProperties().getService().getNotification()
                                .isNotifyMembersAfterOtherMemberInfoUpdated()) {
                            return groupMemberService.queryGroupMemberIds(request.getGroupId())
                                    .collect(Collectors.toSet())
                                    .map(groupMemberIds -> groupMemberIds.isEmpty()
                                            ? RequestHandlerResultFactory.OK
                                            : RequestHandlerResultFactory.get(groupMemberIds, clientRequest.getTurmsRequest()));
                        } else if (!clientRequest.getUserId().equals(request.getMemberId())
                                && node.getSharedProperties().getService().getNotification().isNotifyMemberAfterInfoUpdatedByOthers()) {
                            return Mono.just(RequestHandlerResultFactory.get(
                                    clientRequest.getUserId(),
                                    clientRequest.getTurmsRequest()));
                        }
                        return Mono.just(RequestHandlerResultFactory.OK);
                    }));
        };
    }

}