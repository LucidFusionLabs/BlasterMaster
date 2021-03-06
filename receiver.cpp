/*
 * $Id: receiver.cpp 1336 2014-12-08 09:29:59Z justin $
 */

#include "core/app/network.h"
#include "core/app/net/smtp.h"
#include "core/app/gl/view.h"
#include "core/web/google_chart.h"

namespace LFL { 
DEFINE_int   (gui_port,            0,              "GUI Port");
DEFINE_int   (port,                0,              "Run SMTP server on port");
DEFINE_string(ip,                  "",             "Run SMTP server on comma separated IP list; blank for all");
DEFINE_string(domain,              "",             "SMTP server/client domain; blank for reverse dns");
DEFINE_string(recipients,          "",             "SMTP server accepts RCPT-TO users of all domains in file");
DEFINE_string(configuration_file,  "receiver.cnf", "Regex rule file for storing received mails");

struct MailFilter {
  enum { MAIL_FROM=1, RCPT_TO=2, HEADER=3, CONTENT=4, DEFAULT=5 };
  int type; string regex_pattern, header; Regex regex; File *out;
  MailFilter() : type(0), out(0) {}
  string DebugString() const {
    bool h = type == HEADER, d = type == DEFAULT;
    static const char *typestr[] = { "", "MAIL_FROM", "RCPT_TO", "HEADER", "CONTENT", "DEFAULT" };
    string t = (type > 0 && type < 6) ? string(typestr[type]) : StringPrintf("%d", type);
    return StrCat(t, h?"=":"", h?header:"", d?": ":": /", regex_pattern, d?"":"/ ", out?out->Filename():"/dev/null");
  }
};

struct ReceiverConfig {
  vector<string> domains;
  vector<MailFilter*> filters;
  map<string, vector<MailFilter*> > header_filters;
  map<string, File*> outputs;
  ReceiverConfig() { outputs["/dev/null"] = 0; }

  void OpenDomains(File *f) {
    NextRecordReader nr(f);
    for (const char *line = nr.NextLine(); line; line = nr.NextLine()) domains.push_back(tolower(line));
  }

  void OpenFilters(File *f) {
    NextRecordReader nr(f);
    for (const char *line = nr.NextLine(); line; line = nr.NextLine()) {
      MailFilter filter;

      StringWordIter words(StringPiece(line, nr.record_len), isspace, isint<'/'>);
      string word = words.NextString();
      if (words.Done() || !word[0] || word[0] == '#') continue;

      if      (StringEquals(word, "Catch-all")) { filter.type=MailFilter::DEFAULT; }
      else if (StringEquals(word, "mail-from")) { filter.type=MailFilter::MAIL_FROM; }
      else if (StringEquals(word, "rcpt-to"))   { filter.type=MailFilter::RCPT_TO; }
      else if (StringEquals(word, "header"))    { filter.type=MailFilter::HEADER; filter.header=words.NextString(); }
      else if (StringEquals(word, "content"))   { filter.type=MailFilter::CONTENT; }
      else FATAL("Parse failed '", line, "'");

      if (filter.type != MailFilter::DEFAULT) {
        string regex = words.NextString();
        CHECK(!regex.empty());
        CHECK_EQ(regex[0],              '/');
        CHECK_EQ(regex[regex.size()-1], '/');
        filter.regex = Regex((filter.regex_pattern = regex.substr(1, regex.size()-2)));
      }

      string filename = words.NextString();
      CHECK(!filename.empty());

      map<string, File*>::const_iterator out_i = outputs.find(filename);
      if (out_i != outputs.end()) filter.out = out_i->second;
      else {
        LocalFile *lfo = new LocalFile(filename, "a");
        if (!lfo->Opened()) FATAL("open ", filename, " failed");
        outputs[filename] = lfo;
        filter.out = lfo;
      }

      INFO(filter.DebugString());
      if (filter.type == MailFilter::HEADER) header_filters[filter.header].push_back(new MailFilter(filter));
      else                                                         filters.push_back(new MailFilter(filter));
    }
  }

  MailFilter *Filter(const SMTP::Message &mail) {
    MailFilter *default_filter = 0;
    for (int i = 0; i < filters.size(); i++) {
      MailFilter *f = filters[i];
      if      (f->type == MailFilter::DEFAULT)      { default_filter = f; }
      else if (f->type == MailFilter::MAIL_FROM)    { if (!!f->regex.MatchOne(mail.mail_from)) return f; }
      else if (f->type == MailFilter::CONTENT)      { if (!!f->regex.MatchOne(mail.content)) return f; }
      else if (f->type == MailFilter::RCPT_TO) {
        for (int j=0; j<mail.rcpt_to.size(); j++) { if (!!f->regex.MatchOne(mail.rcpt_to[j])) return f; }
      }
    }

    const char *headers_end = HTTP::FindHeadersEnd(mail.content.c_str());
    if (!headers_end) return default_filter;

    int hlen = headers_end - mail.content.c_str(), hnlen;
    for (const char *h = mail.content.c_str(); h; h = NextLine(StringPiece(h, hlen-(h-mail.content.c_str())))) {
      if (!(hnlen = HTTP::GetHeaderNameLen(h))) continue;
      string hn = string(h, hnlen);
      const char *hv = h+hnlen+2;

      map<string, vector<MailFilter*> >::const_iterator hfi = header_filters.find(hn);
      if (hfi == header_filters.end()) continue;

      for (int i = 0; i < hfi->second.size(); i++) {
        MailFilter *f = hfi->second[i];
        if (!!f->regex.MatchOne(hv)) return f;
      }
    }

    return default_filter;
  }

} receiver_config;

struct MySMTPServer : public SMTPServer {
  map<string, long long> mbox_wrote;
  DeltaSampler *stat_log;
  MySMTPServer() : SMTPServer(""), stat_log(0) {}

  void Open(const string &dom) {
    domain = dom;
    for (map<string, File*>::const_iterator i = receiver_config.outputs.begin(); i != receiver_config.outputs.end(); ++i) 
      if (i->second) mbox_wrote[i->second->Filename()] = 0;

    vector<const long long *> table; vector<string> labels;
    for (map<string, long long>::const_iterator i = mbox_wrote.begin(); i != mbox_wrote.end(); ++i) {
      table.push_back(&i->second); labels.push_back(i->first); 
    }
    stat_log = new DeltaSampler(Seconds(60).count(), table, labels);
  }

  virtual void ReceiveMail(Connection *c, const SMTP::Message &mail) {
    DEBUG("ReceiveMail FROM=", mail.mail_from, ", TO=", mail.rcpt_to, ", content=", mail.content);
    MailFilter *out = receiver_config.Filter(mail);
    File *outfile = out ? out->out : 0;
    if (outfile) {
      MailboxWrite(c, mail, outfile);
      mbox_wrote[outfile->Filename()]++;
    }
    INFO("ReceiveMail FROM=", mail.mail_from, ", TO=", mail.rcpt_to, " OUT=", outfile?outfile->Filename():"/dev/null");
  }

  string StatusLine() const {
    string ret = StrCat("connections=", conn.size());;
    for (map<string, long long>::const_iterator i = mbox_wrote.begin(); i != mbox_wrote.end(); ++i)
      StrAppend(&ret, ", ", i->first, ":", i->second);
    return ret;
  }

  static void MailboxWrite(Connection *c, const SMTP::Message &mail, File *out) {
    out->WriteString(StrCat("From MAILER-DAEMON ", localmboxtime(Now()), "\r\n"));
    out->WriteString(mail.content);
    out->Flush();
  }
} smtp_server;

struct StatusGUI : public HTTPServer::Resource {
  HTTPServer::Response Request(Connection *c, int method, const char *url, const char *args, const char *headers, const char *postdata, int postlen) {
    string response = StrCat("<html><head>\n", GChartsHTML::JSHeader());

    vector<vector<string> > table;
    DeltaGrapher::JSTable(*smtp_server.stat_log, &table, 60);
    if (table.size()>1) StrAppend(&response, GChartsHTML::JSAreaChart("viz1", 600, 400, "Last Hour", "Mails", "Minutes", table));

    StrAppend(&response, GChartsHTML::JSFooter(), "</head><body><h>Receiver Version 1.0</h>\n");
    StrAppend(&response, "<p>FPS=", app->focused->fps.FPS(), ", ", smtp_server.StatusLine(), "</p>\n");
    StrAppend(&response, GChartsHTML::DivElement("viz1", 600, 400), "\n");
    StrAppend(&response, "</body></html>\n");
    return HTTPServer::Response("text/html; charset=UTF-8", &response);
  }
};

int Frame(LFL::Window *W, unsigned clicks, int flag) {
  smtp_server.stat_log->Update();
  char buf[256];
  if (FGets(buf, sizeof(buf))) ERROR("FPS=", W->fps.FPS(), ", ", smtp_server.StatusLine());
  return 0;
}

}; // namespace LFL
using namespace LFL;

extern "C" void MyAppCreate(int argc, const char* const* argv) {
  FLAGS_max_rlimit_core = FLAGS_max_rlimit_open_files = 1;
  FLAGS_enable_network = 1;
  app = new Application(argc, argv);
  app->focused = Window::Create();
  app->focused->frame_cb = Frame;
}

extern "C" int MyAppMain() {
  if (app->Create(__FILE__)) return -1;
  if (app->Init())           return -1;

  if (!FLAGS_configuration_file.empty()) {
    LocalFile lf(FLAGS_configuration_file, "r");
    if (lf.Opened()) receiver_config.OpenFilters(&lf);
  }

  if (!FLAGS_recipients.empty()) {
    LocalFile lf(FLAGS_recipients, "r");
    if (lf.Opened()) receiver_config.OpenDomains(&lf);
  }

  HTTPServer httpd(FLAGS_gui_port, false);
  if (FLAGS_gui_port) {
    httpd.AddURL("/", new StatusGUI());
    if (app->net->Enable(&httpd)) return -1;
  }

  if (FLAGS_port) {
    set<IPV4::Addr> listen_addrs;
    IPV4::ParseCSV(FLAGS_ip, &listen_addrs);
    if (listen_addrs.size()) {
      for (set<IPV4::Addr>::const_iterator i = listen_addrs.begin(); i != listen_addrs.end(); ++i)
        smtp_server.QueueListen(*i, FLAGS_port);
    } else {
      smtp_server.QueueListen(IPV4::ANY, FLAGS_port);
    }
    if (app->net->Enable(&smtp_server)) return -1;

    smtp_server.Open(FLAGS_domain);
    if (smtp_server.domain.empty()) {
      if (!listen_addrs.size()) Sniffer::GetDeviceAddressSet(&listen_addrs);
      for (set<IPV4::Addr>::const_iterator i = listen_addrs.begin(); i != listen_addrs.end(); ++i)
        smtp_server.domains[*i] = SystemNetwork::GetHostByAddr(*i); 
      CHECK_GT(smtp_server.domains.size(), 0);
      smtp_server.domains[IPV4::Parse("0.0.0.0")  ] = "localhost";
      smtp_server.domains[IPV4::Parse("127.0.0.1")] = "localhost";
    }
  }

  if (!FLAGS_port && !FLAGS_gui_port) { INFO("nothing to do"); return 0; }

  int ret = app->Main();
  ERROR("PerformanceTimers: ", Singleton<PerformanceTimers>::Get()->DebugString());
  return ret;
}
