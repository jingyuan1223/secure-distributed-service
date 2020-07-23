# Secure Shared Store Service

## Introduction

This project is to implement a secure distributed service called Secure Shared Store service. According to the different privileges granted, this service allows users to store and retrieve documents with different security levels created by multiple users who access the documents at their local machines.

This project uses the lightweight web framework Flask to achieve communication within client-server model. And to set up node-to-node secure communication channels, the implementation configures Certificate-Based Mutual Authentication with nginx. On the server side, AES encryption and SHA256 hash function are used for encrypted document storage and signature verification.

### Project Directory Structure

The server and client nodes are abstracted as separate folders.

```
├── README.md                   // Project Introduction
├── CA                          // Certificate Authority that stashes CA certificates 
├── server                      // Server Folder
│   ├── application				
│   │	├── documents           // Files sent to server by users for sharing and storing
│   │	├── userpublickeys      // Folder that contains users' public keys
│   │	└── server.py           // Server source code
│   └── certs               	// Server's own public and private keys
├── client1						// Client Node Folder
│   ├── documents				// All files used by users logged in this client node
│   │	├── checkin             // All checkin files by every user 
│   │	└── checkout            // All checkout files by every user
│   ├── certs              		// Client Node's own public and private keys
│   ├── userkeys				// Folders for all users' private keys
│   └── client.py				// Client source code
└── client2                     // Another client node
```

## CA

To implement such a distributed system, we will need to make use of certificates to secure the communication between clients and the server, and to authenticate sources of requests. A Certificate Authority is used to generate certificates for users, client nodes and the server. All nodes trust the CA. 

One can make use of a library such as `OpenSSL` for setting up the CA and to generate certificates. 

When the client keys and certificates are created, they should be placed in the `certs/` folder within the client directory.

## Server

Users should be able to login to the server through any client by providing their private key and session tokens would be generated upon successful authentication of the users.

After a Secure Shared Store server starts, a client node can make requests to the server. The hostname of the server is `secure-shared-store` and the certificate for the server contains `secure-shared-store` as the common name of the server.

Whenever the client node makes a request, mutual authentication is performed and a secure communication channel is established between the client node and the server.

The Secure Shared Store service enables functions including `login`, `checkin`, `checkout`, `grant`, `delete`, and `logout`.

###  Login

`login(User UID, UserPrivateKey)`: This call allows a client node to log into server and convince it that requests made by the client are for the user having UID user-id. The client node will take UID and UserPrivateKey as two separate inputs from the user.

On successful login, the server should return a unique session-token for the user and this session token will have to be included in all the subsequent requests.

### Checkin

`checkin(Document DID, SecurityFlag)`: The document with its id (DID) is sent to the server over the secure channel that was established when the session was initiated. The documents that are to be checked into the server present in the `documents/checkin` folder within the client directory and store in the `server/documents` folder on the server.

The `SecurityFlag` has 2 options: Confidentiality (presented by "1") and Integrity (presented by "2"). The Confidentiality option will make the server encrypt the file using AES and stash it in the encrypted form. And the AES key is also encrypted using server's public key and stored with document meta data. When the flag is set to Integrity, the server will store the document along with a signed copy.

Additionally, when a request is made to checkin a file which is checked out in the current active session, this file should be moved from the checkout folder into the checkin folder.

### Checkout

`checkout(Document DID)`: After a session is established, a user can use this function to request a specific document based on the document identifier (DID) over the secure channel to the server. This file checkout action can only be approved if the requester is the owner of the file or a user who is authorized to perform. Once the document is checked out, it must be stored in the `documents/checkout` folder within the client directory.

The server will access the required file according to the security flag assigned to this file. Under Confidentiality flag, the server will first decrypt the AES key and further decrypt the ciphertext. Under Integrity flag, the server will verify the file content with the saved signature. 

### Grant

`grant(Document DID, TargetUser TUID, AccessRight R, time T)`: Grant action can only be issued by the owner of the document. This will change the defined access control policy to allow the target user (TUID) to have authorization for the specified action (R) for the specified document (DID) for time duration T (in seconds). AccessRight can either be checkin, checkout or both. If the TargetUser is ALL (0), the authorization is granted to all the users in the system for this specific document.

### Delete

`delete(Document DID)`: If the user currently logged in at the requesting client is the document owner, the file is safely deleted.

### Logout

`logout()`: Terminates the current session.  If any documents received from the server were modified, their new copies will be sent to the server before session termination completes. 

## Client

Users should be able to login to the Secure Shared Store server through any client by providing their private key. Session tokens would be generated upon successful authentication of the users. They can then checkin, checkout and delete documents as allowed by access control policies defined by the owner of the document.

After a Secure Shared Store server starts, a client node can make requests to the server. Whenever the client node makes a request, mutual authentication is performed and a secure communication channel is established between the client node and the server. Here, nginx is used to perform mutual authentication (MTLS). Every request from the client node should include the certificate of the client node for authentication.





