// Code generated from the reference implementation (gsm.py). DO NOT EDIT.

package gsm

import "fmt"

// Type is a GS message type.
type Type uint8

// Message types.
const (
	NEWUSERREQUEST         Type = 1
	CONNECTIONREQUEST      Type = 2
	PLAYERNEW              Type = 3
	DISCONNECTION          Type = 4
	PLAYERREMOVED          Type = 5
	EVENT_UDPCONNECT       Type = 6
	NEWS                   Type = 7
	SEARCHPLAYER           Type = 8
	REMOVEACCOUNT          Type = 9
	SERVERSLIST            Type = 11
	SESSIONLIST            Type = 13
	PLAYERLIST             Type = 15
	GETGROUPINFO           Type = 16
	GROUPINFO              Type = 17
	GETPLAYERINFO          Type = 18
	PLAYERINFO             Type = 19
	CHATALL                Type = 20
	CHATLIST               Type = 21
	CHATSESSION            Type = 22
	CHAT                   Type = 24
	CREATESESSION          Type = 26
	SESSIONNEW             Type = 27
	JOINSESSION            Type = 28
	JOINNEW                Type = 31
	LEAVESESSION           Type = 32
	JOINLEAVE              Type = 33
	SESSIONREMOVE          Type = 34
	GSSUCCESS              Type = 38
	GSFAIL                 Type = 39
	BEGINGAME              Type = 40
	UPDATEPLAYERINFO       Type = 45
	MASTERCHANGED          Type = 48
	UPDATESESSIONSTATE     Type = 51
	URGENTMESSAGE          Type = 52
	NEWWAITMODULE          Type = 54
	KILLMODULE             Type = 55
	STILLALIVE             Type = 58
	PING                   Type = 59
	PLAYERKICK             Type = 60
	PLAYERMUTE             Type = 61
	ALLOWGAME              Type = 62
	FORBIDGAME             Type = 63
	GAMELIST               Type = 64
	UPDATEADVERTISMEMENTS  Type = 65
	UPDATENEWS             Type = 66
	VERSIONLIST            Type = 67
	UPDATEVERSIONS         Type = 68
	UPDATEDISTANTROUTERS   Type = 70
	ADMINLOGIN             Type = 71
	STAT_PLAYER            Type = 72
	STAT_GAME              Type = 73
	UPDATEFRIEND           Type = 74
	ADDFRIEND              Type = 75
	DELFRIEND              Type = 76
	LOGINWAITMODULE        Type = 77
	LOGINFRIENDS           Type = 78
	ADDIGNOREFRIEND        Type = 79
	DELIGNOREFRIEND        Type = 80
	STATUSCHANGE           Type = 81
	JOINARENA              Type = 82
	LEAVEARENA             Type = 83
	IGNORELIST             Type = 84
	IGNOREFRIEND           Type = 85
	GETARENA               Type = 86
	GETSESSION             Type = 87
	PAGEPLAYER             Type = 88
	FRIENDLIST             Type = 89
	PEERMSG                Type = 90
	PEERPLAYER             Type = 91
	DISCONNECTFRIENDS      Type = 92
	JOINWAITMODULE         Type = 93
	LOGINSESSION           Type = 94
	DISCONNECTSESSION      Type = 95
	PLAYERDISCONNECT       Type = 96
	ADVERTISEMENT          Type = 97
	MODIFYUSER             Type = 98
	STARTGAME              Type = 99
	CHANGEVERSION          Type = 100
	PAGER                  Type = 101
	LOGIN                  Type = 102
	PHOTO                  Type = 103
	LOGINARENA             Type = 104
	SQLCREATE              Type = 106
	SQLSELECT              Type = 107
	SQLDELETE              Type = 108
	SQLSET                 Type = 109
	SQLSTAT                Type = 110
	SQLQUERY               Type = 111
	ROUTEURLIST            Type = 127
	DISTANCEVECTOR         Type = 131
	WRAPPEDMESSAGE         Type = 132
	CHANGEFRIEND           Type = 133
	NEWRELFRIEND           Type = 134
	DELRELFRIEND           Type = 135
	NEWIGNOREFRIEND        Type = 136
	DELETEIGNOREFRIEND     Type = 137
	ARENACONNECTION        Type = 138
	ARENADISCONNECTION     Type = 139
	ARENAWAITMODULE        Type = 140
	ARENANEW               Type = 141
	NEWBASICGROUP          Type = 143
	ARENAREMOVED           Type = 144
	DELETEBASICGROUP       Type = 145
	SESSIONSBEGIN          Type = 146
	GROUPDATA              Type = 148
	ARENA_MESSAGE          Type = 151
	ARENALISTREQUEST       Type = 157
	ROUTERPLAYERNEW        Type = 158
	BASEGROUPREQUEST       Type = 159
	UPDATEPLAYERPING       Type = 166
	UPDATEGROUPSIZE        Type = 169
	SLEEP                  Type = 179
	WAKEUP                 Type = 180
	SYSTEMPAGE             Type = 181
	SESSIONOPEN            Type = 189
	SESSIONCLOSE           Type = 190
	LOGINCLANMANAGER       Type = 192
	DISCONNECTCLANMANAGER  Type = 193
	CLANMANAGERPAGE        Type = 194
	UPDATECLANPLAYER       Type = 195
	PLAYERCLANS            Type = 196
	GETPERSISTANTGROUPINFO Type = 199
	UPDATEGROUPPING        Type = 202
	DEFERREDGAMESTARTED    Type = 203
	PROXY_HANDLER          Type = 204
	BEGINCLIENTHOSTGAME    Type = 205
	LOBBY_MSG              Type = 209
	LOBBYSERVERLOGIN       Type = 210
	SETGROUPSZDATA         Type = 211
	GROUPSZDATA            Type = 212
	KEY_EXCHANGE           Type = 219
	NAT                    Type = 221
)

var typeNames = map[Type]string{
	NEWUSERREQUEST:         "NEWUSERREQUEST",
	CONNECTIONREQUEST:      "CONNECTIONREQUEST",
	PLAYERNEW:              "PLAYERNEW",
	DISCONNECTION:          "DISCONNECTION",
	PLAYERREMOVED:          "PLAYERREMOVED",
	EVENT_UDPCONNECT:       "EVENT_UDPCONNECT",
	NEWS:                   "NEWS",
	SEARCHPLAYER:           "SEARCHPLAYER",
	REMOVEACCOUNT:          "REMOVEACCOUNT",
	SERVERSLIST:            "SERVERSLIST",
	SESSIONLIST:            "SESSIONLIST",
	PLAYERLIST:             "PLAYERLIST",
	GETGROUPINFO:           "GETGROUPINFO",
	GROUPINFO:              "GROUPINFO",
	GETPLAYERINFO:          "GETPLAYERINFO",
	PLAYERINFO:             "PLAYERINFO",
	CHATALL:                "CHATALL",
	CHATLIST:               "CHATLIST",
	CHATSESSION:            "CHATSESSION",
	CHAT:                   "CHAT",
	CREATESESSION:          "CREATESESSION",
	SESSIONNEW:             "SESSIONNEW",
	JOINSESSION:            "JOINSESSION",
	JOINNEW:                "JOINNEW",
	LEAVESESSION:           "LEAVESESSION",
	JOINLEAVE:              "JOINLEAVE",
	SESSIONREMOVE:          "SESSIONREMOVE",
	GSSUCCESS:              "GSSUCCESS",
	GSFAIL:                 "GSFAIL",
	BEGINGAME:              "BEGINGAME",
	UPDATEPLAYERINFO:       "UPDATEPLAYERINFO",
	MASTERCHANGED:          "MASTERCHANGED",
	UPDATESESSIONSTATE:     "UPDATESESSIONSTATE",
	URGENTMESSAGE:          "URGENTMESSAGE",
	NEWWAITMODULE:          "NEWWAITMODULE",
	KILLMODULE:             "KILLMODULE",
	STILLALIVE:             "STILLALIVE",
	PING:                   "PING",
	PLAYERKICK:             "PLAYERKICK",
	PLAYERMUTE:             "PLAYERMUTE",
	ALLOWGAME:              "ALLOWGAME",
	FORBIDGAME:             "FORBIDGAME",
	GAMELIST:               "GAMELIST",
	UPDATEADVERTISMEMENTS:  "UPDATEADVERTISMEMENTS",
	UPDATENEWS:             "UPDATENEWS",
	VERSIONLIST:            "VERSIONLIST",
	UPDATEVERSIONS:         "UPDATEVERSIONS",
	UPDATEDISTANTROUTERS:   "UPDATEDISTANTROUTERS",
	ADMINLOGIN:             "ADMINLOGIN",
	STAT_PLAYER:            "STAT_PLAYER",
	STAT_GAME:              "STAT_GAME",
	UPDATEFRIEND:           "UPDATEFRIEND",
	ADDFRIEND:              "ADDFRIEND",
	DELFRIEND:              "DELFRIEND",
	LOGINWAITMODULE:        "LOGINWAITMODULE",
	LOGINFRIENDS:           "LOGINFRIENDS",
	ADDIGNOREFRIEND:        "ADDIGNOREFRIEND",
	DELIGNOREFRIEND:        "DELIGNOREFRIEND",
	STATUSCHANGE:           "STATUSCHANGE",
	JOINARENA:              "JOINARENA",
	LEAVEARENA:             "LEAVEARENA",
	IGNORELIST:             "IGNORELIST",
	IGNOREFRIEND:           "IGNOREFRIEND",
	GETARENA:               "GETARENA",
	GETSESSION:             "GETSESSION",
	PAGEPLAYER:             "PAGEPLAYER",
	FRIENDLIST:             "FRIENDLIST",
	PEERMSG:                "PEERMSG",
	PEERPLAYER:             "PEERPLAYER",
	DISCONNECTFRIENDS:      "DISCONNECTFRIENDS",
	JOINWAITMODULE:         "JOINWAITMODULE",
	LOGINSESSION:           "LOGINSESSION",
	DISCONNECTSESSION:      "DISCONNECTSESSION",
	PLAYERDISCONNECT:       "PLAYERDISCONNECT",
	ADVERTISEMENT:          "ADVERTISEMENT",
	MODIFYUSER:             "MODIFYUSER",
	STARTGAME:              "STARTGAME",
	CHANGEVERSION:          "CHANGEVERSION",
	PAGER:                  "PAGER",
	LOGIN:                  "LOGIN",
	PHOTO:                  "PHOTO",
	LOGINARENA:             "LOGINARENA",
	SQLCREATE:              "SQLCREATE",
	SQLSELECT:              "SQLSELECT",
	SQLDELETE:              "SQLDELETE",
	SQLSET:                 "SQLSET",
	SQLSTAT:                "SQLSTAT",
	SQLQUERY:               "SQLQUERY",
	ROUTEURLIST:            "ROUTEURLIST",
	DISTANCEVECTOR:         "DISTANCEVECTOR",
	WRAPPEDMESSAGE:         "WRAPPEDMESSAGE",
	CHANGEFRIEND:           "CHANGEFRIEND",
	NEWRELFRIEND:           "NEWRELFRIEND",
	DELRELFRIEND:           "DELRELFRIEND",
	NEWIGNOREFRIEND:        "NEWIGNOREFRIEND",
	DELETEIGNOREFRIEND:     "DELETEIGNOREFRIEND",
	ARENACONNECTION:        "ARENACONNECTION",
	ARENADISCONNECTION:     "ARENADISCONNECTION",
	ARENAWAITMODULE:        "ARENAWAITMODULE",
	ARENANEW:               "ARENANEW",
	NEWBASICGROUP:          "NEWBASICGROUP",
	ARENAREMOVED:           "ARENAREMOVED",
	DELETEBASICGROUP:       "DELETEBASICGROUP",
	SESSIONSBEGIN:          "SESSIONSBEGIN",
	GROUPDATA:              "GROUPDATA",
	ARENA_MESSAGE:          "ARENA_MESSAGE",
	ARENALISTREQUEST:       "ARENALISTREQUEST",
	ROUTERPLAYERNEW:        "ROUTERPLAYERNEW",
	BASEGROUPREQUEST:       "BASEGROUPREQUEST",
	UPDATEPLAYERPING:       "UPDATEPLAYERPING",
	UPDATEGROUPSIZE:        "UPDATEGROUPSIZE",
	SLEEP:                  "SLEEP",
	WAKEUP:                 "WAKEUP",
	SYSTEMPAGE:             "SYSTEMPAGE",
	SESSIONOPEN:            "SESSIONOPEN",
	SESSIONCLOSE:           "SESSIONCLOSE",
	LOGINCLANMANAGER:       "LOGINCLANMANAGER",
	DISCONNECTCLANMANAGER:  "DISCONNECTCLANMANAGER",
	CLANMANAGERPAGE:        "CLANMANAGERPAGE",
	UPDATECLANPLAYER:       "UPDATECLANPLAYER",
	PLAYERCLANS:            "PLAYERCLANS",
	GETPERSISTANTGROUPINFO: "GETPERSISTANTGROUPINFO",
	UPDATEGROUPPING:        "UPDATEGROUPPING",
	DEFERREDGAMESTARTED:    "DEFERREDGAMESTARTED",
	PROXY_HANDLER:          "PROXY_HANDLER",
	BEGINCLIENTHOSTGAME:    "BEGINCLIENTHOSTGAME",
	LOBBY_MSG:              "LOBBY_MSG",
	LOBBYSERVERLOGIN:       "LOBBYSERVERLOGIN",
	SETGROUPSZDATA:         "SETGROUPSZDATA",
	GROUPSZDATA:            "GROUPSZDATA",
	KEY_EXCHANGE:           "KEY_EXCHANGE",
	NAT:                    "NAT",
}

// Known reports whether the type is one the game uses.
func (t Type) Known() bool { _, ok := typeNames[t]; return ok }

func (t Type) String() string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("TYPE(%d)", uint8(t))
}

// LobbyMsg is a LOBBY_MSG subtype.
type LobbyMsg int

// Lobby message subtypes.
const (
	LobbyJoinServer             LobbyMsg = 3
	LobbyInfoRefresh            LobbyMsg = 6
	LobbyGroupLeave             LobbyMsg = 8
	LobbyGroupInfoGet           LobbyMsg = 9
	LobbyPlayerKick             LobbyMsg = 10
	LobbyCreateRoom             LobbyMsg = 12
	LobbyParentGroupId          LobbyMsg = 14
	LobbyStartGame              LobbyMsg = 15
	LobbyStartMatch             LobbyMsg = 17
	LobbyLobbyDisconnection     LobbyMsg = 18
	LobbyRemoveServer           LobbyMsg = 19
	LobbyLogin                  LobbyMsg = 21
	LobbyJoinLobby              LobbyMsg = 23
	LobbyJoinRoom               LobbyMsg = 24
	LobbyMasterNew              LobbyMsg = 27
	LobbySubmitMatch            LobbyMsg = 30
	LobbyGroupConfigUpdateRes   LobbyMsg = 31
	LobbyUpdatePing             LobbyMsg = 32
	LobbyGameReady              LobbyMsg = 33
	LobbyGameConnected          LobbyMsg = 34
	LobbyGameFinish             LobbyMsg = 35
	LobbyPlayerBan              LobbyMsg = 36
	LobbyPlayerUnban            LobbyMsg = 40
	LobbyUpdateGameInfo         LobbyMsg = 41
	LobbySetPlayerInfo          LobbyMsg = 42
	LobbyLobbyDisconnectAll     LobbyMsg = 43
	LobbyPlayerMatchStarted     LobbyMsg = 44
	LobbyMatchFinish            LobbyMsg = 45
	LobbyGetAltGroupInfo        LobbyMsg = 46
	LobbyMemberJoin             LobbyMsg = 50
	LobbyMemberLeave            LobbyMsg = 51
	LobbyGroupInfo              LobbyMsg = 53
	LobbyNewGroup               LobbyMsg = 54
	LobbyGroupRemove            LobbyMsg = 55
	LobbyGameStarted            LobbyMsg = 56
	LobbyGroupConfigUpdate      LobbyMsg = 57
	LobbyMasterChanged          LobbyMsg = 59
	LobbyKickOut                LobbyMsg = 61
	LobbyMatchStarted           LobbyMsg = 62
	LobbyPlayerBanned           LobbyMsg = 63
	LobbyPlayerBanlist          LobbyMsg = 64
	LobbyMatchReady             LobbyMsg = 65
	LobbyPlayerInfoUpdate       LobbyMsg = 66
	LobbyPlayerUpdateStatus     LobbyMsg = 69
	LobbyPlayerMatchFinished    LobbyMsg = 70
	LobbyFinalMatchResults      LobbyMsg = 71
	LobbyPlayerGroupGet         LobbyMsg = 106
	LobbyChangeRequestedLobbies LobbyMsg = 109
	LobbyMemberList             LobbyMsg = 151
)

var lobbyNames = map[LobbyMsg]string{
	LobbyJoinServer:             "JOIN_SERVER",
	LobbyInfoRefresh:            "INFO_REFRESH",
	LobbyGroupLeave:             "GROUP_LEAVE",
	LobbyGroupInfoGet:           "GROUP_INFO_GET",
	LobbyPlayerKick:             "PLAYER_KICK",
	LobbyCreateRoom:             "CREATE_ROOM",
	LobbyParentGroupId:          "PARENT_GROUP_ID",
	LobbyStartGame:              "START_GAME",
	LobbyStartMatch:             "START_MATCH",
	LobbyLobbyDisconnection:     "LOBBY_DISCONNECTION",
	LobbyRemoveServer:           "REMOVE_SERVER",
	LobbyLogin:                  "LOGIN",
	LobbyJoinLobby:              "JOIN_LOBBY",
	LobbyJoinRoom:               "JOIN_ROOM",
	LobbyMasterNew:              "MASTER_NEW",
	LobbySubmitMatch:            "SUBMIT_MATCH",
	LobbyGroupConfigUpdateRes:   "GROUP_CONFIG_UPDATE_RES",
	LobbyUpdatePing:             "UPDATE_PING",
	LobbyGameReady:              "GAME_READY",
	LobbyGameConnected:          "GAME_CONNECTED",
	LobbyGameFinish:             "GAME_FINISH",
	LobbyPlayerBan:              "PLAYER_BAN",
	LobbyPlayerUnban:            "PLAYER_UNBAN",
	LobbyUpdateGameInfo:         "UPDATE_GAME_INFO",
	LobbySetPlayerInfo:          "SET_PLAYER_INFO",
	LobbyLobbyDisconnectAll:     "LOBBY_DISCONNECT_ALL",
	LobbyPlayerMatchStarted:     "PLAYER_MATCH_STARTED",
	LobbyMatchFinish:            "MATCH_FINISH",
	LobbyGetAltGroupInfo:        "GET_ALT_GROUP_INFO",
	LobbyMemberJoin:             "MEMBER_JOIN",
	LobbyMemberLeave:            "MEMBER_LEAVE",
	LobbyGroupInfo:              "GROUP_INFO",
	LobbyNewGroup:               "NEW_GROUP",
	LobbyGroupRemove:            "GROUP_REMOVE",
	LobbyGameStarted:            "GAME_STARTED",
	LobbyGroupConfigUpdate:      "GROUP_CONFIG_UPDATE",
	LobbyMasterChanged:          "MASTER_CHANGED",
	LobbyKickOut:                "KICK_OUT",
	LobbyMatchStarted:           "MATCH_STARTED",
	LobbyPlayerBanned:           "PLAYER_BANNED",
	LobbyPlayerBanlist:          "PLAYER_BANLIST",
	LobbyMatchReady:             "MATCH_READY",
	LobbyPlayerInfoUpdate:       "PLAYER_INFO_UPDATE",
	LobbyPlayerUpdateStatus:     "PLAYER_UPDATE_STATUS",
	LobbyPlayerMatchFinished:    "PLAYER_MATCH_FINISHED",
	LobbyFinalMatchResults:      "FINAL_MATCH_RESULTS",
	LobbyPlayerGroupGet:         "PLAYER_GROUP_GET",
	LobbyChangeRequestedLobbies: "CHANGE_REQUESTED_LOBBIES",
	LobbyMemberList:             "MEMBER_LIST",
}

// Known reports whether the subtype is one the game uses.
func (s LobbyMsg) Known() bool { _, ok := lobbyNames[s]; return ok }

func (s LobbyMsg) String() string {
	if n, ok := lobbyNames[s]; ok {
		return n
	}
	return fmt.Sprintf("LOBBY_MSG(%d)", int(s))
}
