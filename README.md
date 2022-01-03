<p align="center">
  <img height="100" src="https://raw.githubusercontent.com/turms-im/assets/9dbc34a9d78a68f9f7df2430b4066c82bf8a458f/logo/logo.svg">
</p>

[简体中文](https://github.com/turms-im/turms/blob/develop/README_zh.md)

## What is Turms

Turms is the most advanced open-source instant messaging engine for 100K~10M concurrent users in the world.
Please refer to [Turms Documentation](https://turms-im.github.io/docs) (no English version for now) for details.

## Playground
(Version of demo servers: `ghcr.io/turms-im/turms-admin:latest`, `ghcr.io/turms-im/turms-gateway:latest`, `ghcr.io/turms-im/turms-service:latest`)

* turms-admin: http://playground.turms.im:6510

  Both the account and the password are: `guest`. (The account is allowed to query and add data, but is not allowed to update and delete data.)

* turms-gateway: http://playground.turms.im:10510 (port for WebSocket access) and http://playground.turms.im:11510 (port for TCP access)

* turms-service (Admin API in dev environment with fake data supported): http://playground.turms.im:8510

* Prometheus: http://playground.turms.im:9090; Grafana: http://playground.turms.im:3000

You can use any turms-client-(java/js/swift) implementation to send requests to turms-gateway and interact with other users.

In addition, Playground is set up automatically by just one command: `ENV=dev,demo docker-compose -f docker-compose.standalone.yml --profile monitoring up --force-recreate -d`

## Quick Start
Running the following commands to setup a minimum viable cluster (including turms-gateway, turms-service and turms-admin) and its dependent servers (MongoDB sharded cluster and Redis) automatically:
```sh
git clone --depth 1 https://github.com/turms-im/turms.git
cd turms
docker plugin install grafana/loki-docker-driver:latest --alias loki --grant-all-permissions
docker-compose -f docker-compose.standalone.yml up --force-recreate
```
After the cluster is set up, you can visit turms-admin at http://localhost:6510, and enter the account and password (`turms` by default). If you log in successfully, it means that the cluster of Turms has been setup successfully.

You can also apply the Terraform modules provided by Turms to quickly purchase cloud services and set up a turms cluster (uses spot instances by default). After running `terraform apply`, wait for about 3~15 minutes (Alibaba Cloud ECS is slow to pull ghcr images), and then visit `http://<public IP>:6510`, if you can access turms-admin, it means that the turms cluster has been set up successfully.

**（Note: The following commands will automatically purchase cloud services and deduct the corresponding fees from your account）**

```sh
git clone --depth 1 https://github.com/turms-im/turms.git
cd turms/terraform/alicloud/playground
export ALICLOUD_ACCESS_KEY=<your_access_key>
export ALICLOUD_SECRET_KEY=<your_secret_key>
terraform init
terraform apply
```

## Intro

The architecture of Turms depends on the fanout read design for creating inboxes (or message timelines), and Turms supports push model, pull model, and push-pull model to be aware of the changes of business data (For details, [Business Data Change Awareness](https://turms-im.github.io/docs/for-developers/status-aware.html)). Most of the other design details also come from commercial IM projects.

And compared to many projects with obsolete technology stacks, Turms is also the only open source IM solution that is based on modern architecture and modern technology and is suitable for medium to large scale applications.

In addition, architecture design is an art of trade-off. Some IM products take rich features as their slogan at the cost of no support for medium to large scale applications (they are only suitable for team communications). However, Turms takes extreme performance as the first priority and supports complete (rather than rich) IM features to support medium and large-scale applications. Please refer to [Turms Schema Design](https://turms-im.github.io/docs/for-developers/schema.html) and [Observability](https://turms-im.github.io/docs/for-developers/observability.html) for details.

When you need to compare Turms with other open source IM projects for features, you can first compare Turms with other open source IM projects based on the following features of Turms. Usually, you can find the differences between professional IM projects and amateur IM projects. In addition, under the chapter of `Product Comparison`, we also mentioned the shortcomings of the Turms project for your reference.

Note: The main disadvantage of the current Turms project is that it does not provide support for living/chat room. The technical implementation of the living/chat room is not difficult, but the product requirements, quality attribute requirements, and restrictive conditions are quite different from the scenarios of general social applications, so the first version of Turms does not provide support for it. In addition, Turms is also not suitable for small-scale enterprise communication scenarios. Using Turms for enterprise communication scenarios is using a sledgehammer to crack a nut, because enterprise communication emphasizes feature-rich rather than extreme performance, which is inconsistent with the goals of Turms, so their designs are also different. If you want to support enterprise communication scenarios, you need to develop based on Turms yourselves.

### Business Features

1. Support a complete set of [IM features](https://turms-im.github.io/docs/features). Turms supports almost all IM features supported by commercial instant messaging products and no restrictions on business features. For example, Turms supports advanced features as unwanted words filtering (using Aho-Corasick automaton with double array trie).
    (The data analysis feature will be supported when turms-data is released in the future. Please refer to [Turms Data Analysis](https://turms-im.github.io/docs/for-developers/data-analytics.html ) for details)
2. (Extensibility) Turms supports two approaches to extend: configuration properties and custom plugins. Of course, you can also modify the source code. For example, the plugin turms-plugin-minio based on turms-plugin is used to interact with MinIO server.
2. (Flexibility) Turms provides hundreds of configuration properties for developers to meet various requirements. And most of the properties can be updated at the cluster level when the cluster is running without performance loss.

### Common Architecture Features

1. (Agility) Support updating Turms servers without the users' awareness of shutdown to support rapid iteration
2. (Scalability) The Turms server is stateless to be scaled out; Support multi-active across data centers
3. (Deployability) Support container deployment to facilitate integration (CI/CD) with cloud services. Turms provides three solutions for container deployment out of the box: docker image, docker-compose script, and Terraform module
4. (Observability) Support relatively complete features of observability for business analysis and troubleshoot
5. (Scalability) Support medium to large scale instant messaging applications, and there is no need to refactor even if the application becomes large from medium-scale (There is still a lot of optimization work to be done for large applications, but Turms servers are easy to upgrade)
6. (Security) Support throttling API requests and blocking user/IP to resist most CC attacks
7. (Simplicity) The Turms architecture is lightweight, which makes Turms easy to learn and redevelop. Please refer to [Turms Architecture Design](https://turms-im.github.io/docs/for-developers/architecture.html) for details)
8. Turms depends on the MongoDB sharded cluster to support request routing (such as read-write separation) for medium to large scale applications

### Other Features

1. Observable system (Please refer to [Observability](https://turms-im.github.io/docs/for-developers/observability.html) for details)
   * Log (for events): Turms provides three types of logs: monitoring log, business log, and statistics log
   
   * Metrics (for aggregable data). It reflects the real-time status of the system and business data
   
   * Tracing
   
   Note that the Turms server will provide more monitoring features that can be implemented efficiently as much as possible, but will not provide some common features that have a great impact on performance and are more suitable for third-party services to provide (such as DAU). For this kind of extended feature, you can implement them by offline or real-time analysis of the logs or metrics of Turms servers.
2. Extreme performance
    We always try to archive extreme performance in the implementation of all business workflows. Please refer to the source code for details.
  * Network
    * I/O: The Turms server is a reactive application. All network I/O operations (e.g. database call, Redis call, service discovery call, RPC) are based on Netty to achieve non-blocking I/O. Therefore, the Turms server can make full use of system resources (while traditional servers can't)
    * Encoding: Protobuf is used to encode the traffic data between Turms servers and turms clients; Custom encoding without any redundant data is used to encode the RPC requests and responses between Turms servers to ensure extreme efficiency
  * Thread
      * The Turms server has an excellent thread model, and its thread number is constant, which is independent of the number of online users and the number of requests. Since the default number of threads in the access layer of the Turms server is the same as that of the CPU processors, the Turms server can make full use of the CPU cache, and greatly reduce the cost of thread context switching compared with traditional servers
      * During business logic processing, there is no synchronization or lock, only CAS
  * Memory
      * The Turms server allocates heap or direct memory smartly according to its usage to reduce the memory footprint 
      * The Turms server refactors parts of MongoDB/Redis client dependencies to ensure that there is no redundant memory allocation in the Turms server, which greatly improves the effective use of memory
  * Cache: The Turms server makes full use of the local memory cache
## Subprojects

|Name | Summary |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| <span style="white-space:nowrap;"> turms-gateway </span> | A gateway (push server) interacting with clients, and responsible for user authentication, session management, push notification, and load balancing for turms-service servers |
| <span style="white-space:nowrap;"> turms-service</span> |Implements IM business logic, and provides admins with business data management, RBAC, cluster management|
| <span style="white-space:nowrap;"> turms-admin</span> |Provides features such as business data management and cluster management for Turms server cluster|
| <span style="white-space:nowrap;"> turms-client-js</span> | Exposes APIs to interact with the Turms server to implement IM features and underlying driver logic (such as heartbeat). You don't need to know its implementations because it's transparent for developers |
| <span style="white-space:nowrap;"> turns-client-kotlin</span> | ditto|
| <span style="white-space:nowrap;"> turns-client-swift </span> | ditto|
| <span style="white-space:nowrap;"> turms-plugin </span> | When events (such as user going online/offline, message receiving and forwarding, etc) are fired, turms-gateway and turms-service will trigger corresponding custom plugins to facilitate developers to implement custom features |
| <span style="white-space:nowrap;">turms-plugin-antispam</span> | A plugin based on turms-plugin for the anti-spam protection using Aho-Corasick automaton with double array trie (The time complexity of detection is O(n), and n is the length of target string code points) |
| <span style="white-space:nowrap;"> turms-plugin-minio</span> |A plugin based on turms-plugin for the storage service, and is used to interact with MinIO server|
| <span style="white-space:nowrap;"> turms-data (TODO)</span> | Not yet published. An independent data analysis system based on Flink ecosystem is responsible for business data analysis, and provides underlying data support for the statistics APIs of turms for admins and operational reports of turms-admin |

## Reference Architecture

The architecture design of Turms is derived from commercial instant messaging architectures. The following figure shows the reference architecture of Turms. The services framed by dotted lines are optional services, while the services framed by solid lines are required services. Please refer to [Turms Architecture Design](https://turms-im.github.io/docs/for-developers/architecture.html) for details.

![](https://raw.githubusercontent.com/turms-im/assets/master/turms/reference-architecture.png)

## Product Comparison

|                       | [Rocket.Chat](https://github.com/RocketChat/Rocket.Chat)     | Closed source IM cloud                                       | Turms                                                        |
| --------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ |
| Application scenarios | Team communications                                          | General IM scenarios                                         | General medium to large scale IM scenarios (Making Turms possible for redevelopment)<br />(Note: The first version of Turms does not provide support for living/chat room) |
| Advantages            | 1. Provide cloud services by just clicking the mouse to start the cluster and provide services<br />2. The client implementation is cross-platform and out-of-the-box for users<br/>3. Support a complete and unified UI suite<br/>4. Support rich advanced instant messaging features, such as audio and video conference, file sharing, screen sharing <br/>5. Provide commercial users with technical support | 1. Provide cloud services by just clicking the mouse to start the cluster and provide services<br />2. The client implementation is cross-platform and out-of-the-box for users<br/>3. Support a complete and unified UI suite<br/>4. Support rich advanced instant messaging features, such as audio and video conference, file sharing, screen sharing <br/>5. Provide commercial users with technical support | The advantages are the features described above              |
| Disadvantages         | 1. Only suitable for small-scale applications<br/>2. Narrow application scenarios and hard to customize | 1. It is closed source and cannot be customized. Any project will inevitably have new business requirements after business growth, which needs to be customized. However, IM clouds either do not provide customized services or require high customization fees, and they may misunderstand your requirements, resulting in customized features that cannot meet your business needs well. It will take long-term cooperation to works well with them.<br />But based on Turms, your requirements can be implemented and provided quickly, and the cost is low.<br />Note: For details of the complexity of IM, you can refer to [Schema Design](https://turms-im.github.io/docs/for-developers/schema.html#%E9%9C%80%E6%B1%82%E5%88%86%E6%9E%90%E4%B8%8E%E9%9B%86%E5%90%88%E7%BB%93%E6%9E%84%E8%AE%BE%E8%AE%A1)<br/>2. Data Privacy. All your user information and message data are stored on IM clouds, which can peep and use your data.<br />Especially for some small IM companies, the data security is not guaranteed at all, and you even need to bear the risk of unrecoverable data loss.<br/>3. The more you use IM clouds, the more you rely on it,  the more expensive it is. Most IM clouds provide a certain free quota or trial period, but after the user scale of your product grows, you need to pay a high usage fee or give up the use to start develop your own IM server<br/>4. Technical support is not timely. IM clouds need to provide technical support to a lot of customers at the same time, and the support for your product may lag behind | 1. Only meets the general instant messaging needs, and does not provide some advanced features (for example, no support for audio and video conferencing)<br/>2. The first version of Turms does not support living/chat room<br />3. Turms server only provides raw data of metrics/logs, and does not provide functions such as analysis and alarms<br />4. The web-based system administration `turms-admin` does not provide advanced operation features currently <br/>5. No support for specific business logic and UI<br />6. Servers are reactive, which is challenging for some developers |
| Comment               | It is highly recommended to use Rocket.Chat for team communications | If the IM business scenarios in your product is very common, and there is no custom requirements, and the IM business is not the main business of your product, it is recommended to use IM clouds.<br />But if there is no special requirements, try not to use the IM cloud provided by small companies, otherwise your data security will not be guaranteed | Although both are open source IM projects, they have completely different application scenarios. Turms is a general instant messaging engine for medium to large scale instant messaging applications. You cannot just hand Turms to your customers (just as most products don't let customers write SQL statements to query business data in the database). <br/>However, based on Turms, you can implement all the open-source instant messaging projects on GitHub more efficiently, comprehensively, and extensively |

## Demo with Specific Business Implementation

Considering the positioning of Turms, we do not plan to provide client demo with UI and specific business logic in the near future because:

* It is easy for developers to verify the business features supported by Turms. If you just want to test the business features of Turms, you can run the Turms server without even typing a line of code. Only ten lines of code can realize the login, sending messages, sending friends' requests and other business features, or modify properties to customize various requirements.
* The design and implementation of the demo are closely related to the specific business scenarios, specific programming language, specific technical architecture, and specific OS while Turms has been committed to efficiently meeting various complex and challenging instant messaging scenarios, and we don't want to publish a demo that limits the imagination of developers. And developing and maintaining a demo is also very time-consuming and will slow down the progress of the development of Turms.
