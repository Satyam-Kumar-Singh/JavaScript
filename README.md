# JavaScript
import { OnGatewayConnection, OnGatewayDisconnect, OnGatewayInit, SubscribeMessage, WebSocketGateway, WebSocketServer } from "@nestjs/websockets";
import { Server, Socket } from "socket.io";
import { Logger } from "@nestjs/common";
import { JwtAuthService } from "../auth/jwtAuth.service";
import { ChatService } from "./chat.service";

@WebSocketGateway({
    namespace: 'project-chat',
    cors: {
        origin: ['http://localhost:3000','http://localhost:3001','http://localhost:3002','http://localhost:3003'],
        credentials: false
    }
})
export class ChatSocketGateway implements OnGatewayInit, OnGatewayConnection, OnGatewayDisconnect {
    private readonly logger = new Logger(ChatSocketGateway.name);

    @WebSocketServer()
    server: Server;

    constructor(
        private readonly jwtAuthService: JwtAuthService,
        private readonly chatService: ChatService
    ) { }

    // Role hierarchy
    private roleHierarchy = {
        'admin': 1,
        'Management': 2,
        'Supervisors': 3,
        'Accounts': 3,
    };

    afterInit(server: any) {
        this.logger.log('WebSocket server initialized');
    }

    // make connection
    async handleConnection(client: Socket) {
        const token = client.handshake.auth.token;

        if (!token) {
            this.logger.error(`No token provided for client: ${client.id}`);
            return client.disconnect();
        }

        try {
            const userInfo = await this.jwtAuthService.verifyToken(token);
            client.data.user = userInfo;

            if (this.jwtAuthService.isAdmin(token)) {
                this.logger.log(`Admin connected: ${client.id} as ${userInfo.emailid}`);
            } else if (this.jwtAuthService.isUser(token)) {
                this.logger.log(`User connected: ${client.id} as ${userInfo.name} with role ${userInfo.role}`);
            }
        } catch (error) {
            this.logger.error(`Invalid token: ${error.message}`);
            return client.disconnect();
        }
    }

    // disconnect connection
    handleDisconnect(client: Socket) {
        this.logger.log(`Client disconnected: ${client.id}`);
    }

    // join room
    @SubscribeMessage('subscribeToProject')
    handleProjectSubscription(client: Socket, projectId: string) {
        const user = client.data.user;
        const accountId = user.accountid;
        const userRole = user.role.toLowerCase();
        console.log('user data on subscribe', user);

        const mainRoom = `account_${accountId}_project_${projectId}`;
        const managementsRoom = `account_${accountId}_project_${projectId}_managements`;
        const supervisorsRoom = `account_${accountId}_project_${projectId}_supervisors`;
        const accountsRoom = `account_${accountId}_project_${projectId}_accounts`;

        // Admin joins the main room and all subrooms
        if (this.jwtAuthService.isAdmin(client.handshake.auth.token)) {
            client.join(mainRoom);
            this.logger.log(`Admin ${user.emailid} joined main room for project ${projectId}`);

            client.join([managementsRoom, supervisorsRoom, accountsRoom]);
            this.logger.log(`Admin ${user.emailid} joined subrooms: ${managementsRoom}, ${supervisorsRoom}, ${accountsRoom}`);
            return;
        }

        // Check project authorization
        if (!user.projectIds.includes(parseInt(projectId))) {
            this.logger.warn(`User ${user.name} not authorized to subscribe to project: ${projectId}`);
            client.emit('unauthorized', { message: 'You are not authorized to join this project.' });
            return;
        }

        // Join the main room for the project
        client.join(mainRoom);
        this.logger.log(`Client ${client.id} joined main room ${mainRoom}`);

        // Join specific role-based subroom
        if (userRole.includes('manager')) {
            client.join([managementsRoom, supervisorsRoom, accountsRoom]);
            this.logger.log(`User ${user.name} with role ${userRole} joined management subroom`);
        } else if (userRole === 'supervisor') {
            client.join(supervisorsRoom);
            this.logger.log(`User ${user.name} with role ${userRole} joined supervisors subroom`);
        } else if (userRole.includes('accountant')) {
            client.join(accountsRoom);
            this.logger.log(`User ${user.name} with role ${userRole} joined accounts subroom`);
        }

    }

    // leave room
    @SubscribeMessage('unsubscribeFromProject')
    handleProjectUnsubscription(client: Socket, projectId: string) {
        const user = client.data.user;
        const accountId = user.accountid;
        const userRole = user.role.toLowerCase();

        // Main project room
        const mainRoom = `account_${accountId}_project_${projectId}`;
        const managementsRoom = `account_${accountId}_project_${projectId}_managements`;
        const supervisorsRoom = `account_${accountId}_project_${projectId}_supervisors`;
        const accountsRoom = `account_${accountId}_project_${projectId}_accounts`;

        client.leave(mainRoom);
        this.logger.log(`Client ${client.id} left main room`);

        // Leave subrooms based on role
        const subrooms = [managementsRoom, supervisorsRoom, accountsRoom];

        // Check if the user is an admin
        if (this.jwtAuthService.isAdmin(client.handshake.auth.token)) {
            subrooms.forEach(room => client.leave(room));
            this.logger.log(`Admin ${user.emailid} left all subrooms`);

        } else {
            if (userRole.includes('manager')) {
                subrooms.forEach(room => client.leave(room));
                this.logger.log(`User ${user.name} with role ${userRole} left all subrooms`);
            } else if (userRole === 'supervisor') {
                client.join(supervisorsRoom);
                this.logger.log(`User ${user.name} with role ${userRole} left supervisors subroom`);
            } else if (userRole.includes('accountant')) {
                client.join(accountsRoom);
                this.logger.log(`User ${user.name} with role ${userRole} left accounts subroom`);
            }
            this.logger.log(`User ${user.name} unsubscribed from project: ${projectId}`);
        }
    }


    // send message
    @SubscribeMessage('sendMessage')
    handleMessage(
        client: Socket,
        payload: {
            projectId: string,
            message: string,
            isAdminBroadcast?: boolean,
            sendToSupervisors?: boolean,
            sendToAccounts?: boolean
        }
    ) {
        const user = client.data.user;
        const accountId = user.accountid;
        const userRole = user.role.toLowerCase();

        const mainRoom = `account_${accountId}_project_${payload.projectId}`;
        const managementsRoom = `account_${accountId}_project_${payload.projectId}_managements`;
        const supervisorsRoom = `account_${accountId}_project_${payload.projectId}_supervisors`;
        const accountsRoom = `account_${accountId}_project_${payload.projectId}_accounts`;


        if (this.jwtAuthService.isAdmin(client.handshake.auth.token)) {
            if (payload.isAdminBroadcast) {
                this.server.to(mainRoom).emit('receiveMessage', {
                    sender: user.emailid,
                    role: userRole,
                    message: payload.message
                });
                this.logger.log(`Admin broadcasted message in main room ${mainRoom}`);
                return;
            }

            // Always send to the management room by default
            this.server.to(managementsRoom).emit('receiveMessage', {
                sender: user.emailid,
                role: userRole,
                message: payload.message
            });
            this.logger.log(`Admin sent message to managements room ${managementsRoom} - ${payload.message}`);

        } else if (userRole.includes('manager')) {
            if (payload.sendToSupervisors) {
                // If sendToSupervisors flag is set, send message to the supervisors room
                this.server.to(supervisorsRoom).emit('receiveMessage', {
                    sender: user.name,
                    role: userRole,
                    message: payload.message
                });
                this.logger.log(`Management user ${user.name} sent message to supervisors room ${supervisorsRoom}`);
            } else if (payload.sendToAccounts) {
                this.server.to(accountsRoom).emit('receiveMessage', {
                    sender: user.name,
                    role: userRole,
                    message: payload.message
                });
                this.logger.log(`Management user ${user.name} sent message to accounts room `);
            } else {
                // Default: send message to the management room
                this.server.to(managementsRoom).emit('receiveMessage', {
                    sender: user.name,
                    role: userRole,
                    message: payload.message
                });
                this.logger.log(`Management user ${user.name} sent message to management room ${managementsRoom}`);
            }
        } else if (userRole === 'supervisor') {
            this.server.to(supervisorsRoom).emit('receiveMessage', {
                sender: user.name,
                role: userRole,
                message: payload.message
            });
            this.logger.log(`Supervisor user ${user.name} sent message to supervisors room`);
        } else if (userRole.includes('accountant')) {
            this.server.to(accountsRoom).emit('receiveMessage', {
                sender: user.name,
                role: userRole,
                message: payload.message
            });
            this.logger.log(`Accounts user ${user.name} sent message to accounts room`);
        }
    }
}
