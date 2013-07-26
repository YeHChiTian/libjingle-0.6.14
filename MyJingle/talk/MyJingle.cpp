// MyJingle.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#define _CRT_SECURE_NO_DEPRECATE 1

#include <tchar.h>
#include <time.h>

#include <iomanip>
#include <iostream>
#include <string>

#if HAVE_CONFIG_H
#include "config.h"
#endif  // HAVE_CONFIG_H

#if HAVE_OPENSSL_SSL_H
#define USE_SSL_TUNNEL
#endif

#include "talk/base/basicdefs.h"
#include "talk/base/common.h"
#include "talk/base/helpers.h"
#include "talk/base/logging.h"
#include "talk/base/ssladapter.h"
#include "talk/base/stringutils.h"
#include "talk/base/thread.h"
#include "talk/examples/login/autoportallocator.h"
#include "talk/examples/login/xmpppump.h"
#include "talk/examples/login/xmppsocket.h"
#include "talk/p2p/base/sessionmanager.h"
#include "talk/p2p/client/sessionmanagertask.h"
#include "talk/xmpp/xmppengine.h"
#ifdef USE_SSL_TUNNEL
#include "talk/session/tunnel/securetunnelsessionclient.h"
#endif
#include "talk/session/tunnel/tunnelsessionclient.h"
#include "talk/xmpp/xmppclient.h"
#include "talk/xmpp/xmppclientsettings.h"

#ifndef MAX_PATH
#define MAX_PATH 256
#endif

#if defined(_MSC_VER) && (_MSC_VER < 1400)
// The following are necessary to properly link when compiling STL without
// /EHsc, otherwise known as C++ exceptions.
void __cdecl std::_Throw(const std::exception &) {}
std::_Prhand std::_Raise_handler = 0;
#endif

enum {
	MSG_LOGIN_COMPLETE = 1,
	MSG_LOGIN_FAILED,
	MSG_DONE,
};

buzz::Jid gUserJid;
talk_base::InsecureCryptStringImpl gUserPass;
std::string gXmppHost = "talk.google.com";
int gXmppPort = 5222;
buzz::TlsOptions gXmppUseTls = buzz::TLS_REQUIRED;

class DebugLog : public sigslot::has_slots<> {
public:
	DebugLog() :
	  debug_input_buf_(NULL), debug_input_len_(0), debug_input_alloc_(0),
		  debug_output_buf_(NULL), debug_output_len_(0), debug_output_alloc_(0),
		  censor_password_(false)
	  {}
	  char * debug_input_buf_;
	  int debug_input_len_;
	  int debug_input_alloc_;
	  char * debug_output_buf_;
	  int debug_output_len_;
	  int debug_output_alloc_;
	  bool censor_password_;

	  void Input(const char * data, int len) {
		  if (debug_input_len_ + len > debug_input_alloc_) {
			  char * old_buf = debug_input_buf_;
			  debug_input_alloc_ = 4096;
			  while (debug_input_alloc_ < debug_input_len_ + len) {
				  debug_input_alloc_ *= 2;
			  }
			  debug_input_buf_ = new char[debug_input_alloc_];
			  memcpy(debug_input_buf_, old_buf, debug_input_len_);
			  delete[] old_buf;
		  }
		  memcpy(debug_input_buf_ + debug_input_len_, data, len);
		  debug_input_len_ += len;
		  DebugPrint(debug_input_buf_, &debug_input_len_, false);
	  }

	  void Output(const char * data, int len) {
		  if (debug_output_len_ + len > debug_output_alloc_) {
			  char * old_buf = debug_output_buf_;
			  debug_output_alloc_ = 4096;
			  while (debug_output_alloc_ < debug_output_len_ + len) {
				  debug_output_alloc_ *= 2;
			  }
			  debug_output_buf_ = new char[debug_output_alloc_];
			  memcpy(debug_output_buf_, old_buf, debug_output_len_);
			  delete[] old_buf;
		  }
		  memcpy(debug_output_buf_ + debug_output_len_, data, len);
		  debug_output_len_ += len;
		  DebugPrint(debug_output_buf_, &debug_output_len_, true);
	  }

	  static bool
		  IsAuthTag(const char * str, size_t len) {
			  if (str[0] == '<' && str[1] == 'a' &&
				  str[2] == 'u' &&
				  str[3] == 't' &&
				  str[4] == 'h' &&
				  str[5] <= ' ') {
					  std::string tag(str, len);

					  if (tag.find("mechanism") != std::string::npos)
						  return true;

			  }
			  return false;
	  }

void DebugPrint(char * buf, int * plen, bool output) {
		int len = *plen;
		if (len > 0) {
			time_t tim = time(NULL);
			struct tm * now = localtime(&tim);
			char *time_string = asctime(now);
			if (time_string) {
				size_t time_len = strlen(time_string);
				if (time_len > 0) {
					time_string[time_len-1] = 0;    // trim off terminating \n
				}
			}
			LOG(INFO) << (output ? "SEND >>>>>>>>>>>>>>>>>>>>>>>>>" : "RECV <<<<<<<<<<<<<<<<<<<<<<<<<")
				<< " : " << time_string;

			bool indent;
			int start = 0, nest = 3;
			for (int i = 0; i < len; i += 1) {
				if (buf[i] == '>') {
					if ((i > 0) && (buf[i-1] == '/')) {
						indent = false;
					} else if ((start + 1 < len) && (buf[start + 1] == '/')) {
						indent = false;
						nest -= 2;
					} else {
						indent = true;
					}

					// Output a tag
					LOG(INFO) << std::setw(nest) << " " << std::string(buf + start, i + 1 - start);

					if (indent)
						nest += 2;

					// Note if it's a PLAIN auth tag
					if (IsAuthTag(buf + start, i + 1 - start)) {
						censor_password_ = true;
					}

					// incr
					start = i + 1;
				}

				if (buf[i] == '<' && start < i) {
					if (censor_password_) {
						LOG(INFO) << std::setw(nest) << " " << "## TEXT REMOVED ##";
						censor_password_ = false;
					}
					else {
						LOG(INFO) << std::setw(nest) << " " << std::string(buf + start, i - start);
					}
					start = i;
				}
			}
			len = len - start;
			memcpy(buf, buf + start, len);
			*plen = len;
		}
}

};

static DebugLog debug_log_;

// Prints out a usage message then exits.
void Usage() {
	std::cerr << "Usage:" << std::endl;
	std::cerr << "  pcp [options] <my_jid>                             (server mode)" << std::endl;
	std::cerr << "  pcp [options] <my_jid> <src_file> <dst_full_jid>:<dst_file> (client sending)" << std::endl;
	std::cerr << "  pcp [options] <my_jid> <src_full_jid>:<src_file> <dst_file> (client rcv'ing)" << std::endl;
	std::cerr << "           --verbose" << std::endl;
	std::cerr << "           --xmpp-host=<host>" << std::endl;
	std::cerr << "           --xmpp-port=<port>" << std::endl;
	std::cerr << "           --xmpp-use-tls=(true|false)" << std::endl;
	exit(1);
}

// Prints out an error message, a usage message, then exits.
void Error(const std::string& msg) {
	std::cerr << "error: " << msg << std::endl;
	std::cerr << std::endl;
	Usage();
}

void FatalError(const std::string& msg) {
	std::cerr << "error: " << msg << std::endl;
	std::cerr << std::endl;
	exit(1);
}

// Determines whether the given string is an option.  If so, the name and
// value are appended to the given strings.
bool ParseArg(const char* arg, std::string* name, std::string* value) {
	if (strncmp(arg, "--", 2) != 0)
		return false;

	const char* eq = strchr(arg + 2, '=');
	if (eq) {
		if (name)
			name->append(arg + 2, eq);
		if (value)
			value->append(eq + 1, arg + strlen(arg));
	} else {
		if (name)
			name->append(arg + 2, arg + strlen(arg));
		if (value)
			value->clear();
	}

	return true;
}

int ParseIntArg(const std::string& name, const std::string& value) {
	char* end;
	long val = strtol(value.c_str(), &end, 10);
	if (*end != '\0')
		Error(std::string("value of option ") + name + " must be an integer");
	return static_cast<int>(val);
}

#ifdef WIN32
#pragma warning(push)
// disable "unreachable code" warning b/c it varies between dbg and opt
#pragma warning(disable: 4702)
#endif
bool ParseBoolArg(const std::string& name, const std::string& value) {
	if (value == "true")
		return true;
	else if (value == "false")
		return false;
	else {
		Error(std::string("value of option ") + name + " must be true or false");
		return false;
	}
}
#ifdef WIN32
#pragma warning(pop)
#endif

void ParseFileArg(const char* arg, buzz::Jid* jid, std::string* file)
{
	const char* sep = strchr(arg, ':');
	if (!sep) {
		*file = arg;
	} else {
		buzz::Jid jid_arg(std::string(arg, sep-arg));
		if (jid_arg.IsBare())
			Error("A full JID is required for the source or destination arguments.");
		*jid = jid_arg;
		*file = std::string(sep+1);
	}
}

void SetConsoleEcho(bool on) {
#ifdef WIN32
	HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
	if ((hIn == INVALID_HANDLE_VALUE) || (hIn == NULL))
		return;

	DWORD mode;
	if (!GetConsoleMode(hIn, &mode))
		return;

	if (on) {
		mode = mode | ENABLE_ECHO_INPUT;
	} else {
		mode = mode & ~ENABLE_ECHO_INPUT;
	}

	SetConsoleMode(hIn, mode);
#else
	int re;
	if (on)
		re = system("stty echo");
	else
		re = system("stty -echo");
	if (-1 == re)
		return;
#endif
}

// Fills in a settings object with the values from the arguments.
buzz::XmppClientSettings LoginSettings() {
	buzz::XmppClientSettings xcs;
	xcs.set_user(gUserJid.node());
	xcs.set_host(gUserJid.domain());
	xcs.set_resource("pcp");
	xcs.set_pass(talk_base::CryptString(gUserPass));
	talk_base::SocketAddress server(gXmppHost, gXmppPort);
	xcs.set_server(server);
	xcs.set_use_tls(gXmppUseTls);
	return xcs;
}

// Runs the current thread until a message with the given ID is seen.
uint32 Loop(const std::vector<uint32>& ids) {
	talk_base::Message msg;
	while (talk_base::Thread::Current()->Get(&msg)) {
		if (msg.phandler == NULL) {
			if (std::find(ids.begin(), ids.end(), msg.message_id) != ids.end())
				return msg.message_id;
			std::cout << "orphaned message: " << msg.message_id;
			continue;
		}
		talk_base::Thread::Current()->Dispatch(&msg);
	}
	return 0;
}

#ifdef WIN32
#pragma warning(disable:4355)
#endif

class CustomXmppPump : public XmppPumpNotify, public XmppPump
{
public:
	CustomXmppPump() : XmppPump(this), server_(false) { }

	void Serve(cricket::TunnelSessionClient* client) {
		client->SignalIncomingTunnel.connect(this,
			&CustomXmppPump::OnIncomingTunnel);
		server_ = true;
	}

	void OnStateChange(buzz::XmppEngine::State state) {
		switch (state) {
		case buzz::XmppEngine::STATE_START:
			std::cout << "connecting..." << std::endl;
			break;
		case buzz::XmppEngine::STATE_OPENING:
			std::cout << "logging in..." << std::endl;
			break;
		case buzz::XmppEngine::STATE_OPEN:
			std::cout << "logged in..." << std::endl;
			talk_base::Thread::Current()->Post(NULL, MSG_LOGIN_COMPLETE);
			break;
		case buzz::XmppEngine::STATE_CLOSED:
			std::cout << "logged out..." << std::endl;
			talk_base::Thread::Current()->Post(NULL, MSG_LOGIN_FAILED);
			break;
		}
	}

	void OnIncomingTunnel(cricket::TunnelSessionClient* client, buzz::Jid jid,
		std::string description, cricket::Session* session) {
			std::cout << "IncomingTunnel from " << jid.Str()
				<< ": " << description << std::endl;
			if (!server_ || (file_.get() != NULL)) {
				client->DeclineTunnel(session);
				return;
			}
			std::string filename;
			bool send;
			if (strncmp(description.c_str(), "send:", 5) == 0) {
				send = true;
			} else if (strncmp(description.c_str(), "recv:", 5) == 0) {
				send = false;
			} else {
				client->DeclineTunnel(session);
				return;
			}
			filename = description.substr(5);
			talk_base::StreamInterface* stream = client->AcceptTunnel(session);
			if (!ProcessStream(stream, filename, send))
				talk_base::Thread::Current()->Post(NULL, MSG_DONE);

			// TODO: There is a potential memory leak, however, since the PCP
			// app doesn't work right now, I can't verify the fix actually works, so
			// comment out the following line until we fix the PCP app.

			// delete stream;
	}

	bool ProcessStream(talk_base::StreamInterface* stream,
		const std::string& filename, bool send) {
			ASSERT(file_.get() == NULL);
			sending_ = send;
			file_.reset(new talk_base::FileStream);
			buffer_len_ = 0;
			int err;
			if (!file_->Open(filename.c_str(), sending_ ? "rb" : "wb", &err)) {
				std::cerr << "Error opening <" << filename << ">: "
					<< std::strerror(err) << std::endl;
				return false;
			}
			stream->SignalEvent.connect(this, &CustomXmppPump::OnStreamEvent);
			if (stream->GetState() == talk_base::SS_CLOSED) {
				std::cerr << "Failed to establish P2P tunnel" << std::endl;
				return false;
			}
			if (stream->GetState() == talk_base::SS_OPEN) {
				OnStreamEvent(stream,
					talk_base::SE_OPEN | talk_base::SE_READ | talk_base::SE_WRITE, 0);
			}
			return true;
	}

	void OnStreamEvent(talk_base::StreamInterface* stream, int events, int error)
	{

	}

	void Cleanup(talk_base::StreamInterface* stream, bool delay = false) {
		LOG(LS_VERBOSE) << "Closing";
		stream->Close();
		file_.reset();
		if (!server_) {
			if (delay)
				talk_base::Thread::Current()->PostDelayed(2000, NULL, MSG_DONE);
			else
				talk_base::Thread::Current()->Post(NULL, MSG_DONE);
		}
	}

private:
	bool server_, sending_;
	talk_base::scoped_ptr<talk_base::FileStream> file_;
	char buffer_[1024 * 64];
	size_t buffer_len_;
};

int _tmain(int argc, _TCHAR* argv[])
{
	gUserJid = buzz::Jid("zhujianwen0910");
	if (!gUserJid.IsValid())
		Error("bad arguments");

	char path[MAX_PATH];
#if WIN32
	GetCurrentDirectoryA(MAX_PATH, path);
#else
	if (NULL == getcwd(path, MAX_PATH))
		Error("Unable to get current path");
#endif

	std::cout << "Directory: " << std::string(path) << std::endl;

	buzz::Jid gSrcJid;
	buzz::Jid gDstJid;
	std::string gSrcFile;
	std::string gDstFile;

	bool as_server = true;
	ParseFileArg("E:\\Genie\\1.jpg", &gSrcJid, &gSrcFile);
	ParseFileArg("E:\\Genie\\1.jpg", &gDstJid, &gDstFile);
	if(gSrcJid.Str().empty() == gDstJid.Str().empty())
		Error("Exactly one of source JID or destination JID must be empty.");
	as_server = false;

	std::cout << "Password: ";
	SetConsoleEcho(false);
	std::cin >> gUserPass.password();
	SetConsoleEcho(true);
	std::cout << std::endl;

	talk_base::InitializeSSL();
	// Log in.
	CustomXmppPump pump;
	pump.client()->SignalLogInput.connect(&debug_log_, &DebugLog::Input);
	pump.client()->SignalLogOutput.connect(&debug_log_, &DebugLog::Output);
	pump.DoLogin(LoginSettings(), new XmppSocket(gXmppUseTls), 0);
	//new XmppAuth());

	// Wait until login succeeds.
	std::vector<uint32> ids;
	ids.push_back(MSG_LOGIN_COMPLETE);
	ids.push_back(MSG_LOGIN_FAILED);
	if (MSG_LOGIN_FAILED == Loop(ids))
		FatalError("Failed to connect");

	{
		talk_base::scoped_ptr<buzz::XmlElement> presence(
			new buzz::XmlElement(buzz::QN_PRESENCE));
		presence->AddElement(new buzz::XmlElement(buzz::QN_PRIORITY));
		presence->AddText("-1", 1);
		pump.SendStanza(presence.get());
	}

	std::string user_jid_str = pump.client()->jid().Str();
	std::cout << "Logged in as " << user_jid_str << std::endl;

	// Prepare the random number generator.
	talk_base::InitRandom(user_jid_str.c_str(), user_jid_str.size());

	return 0;
}

