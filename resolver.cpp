/*
 * $Id: resolver.cpp 1314 2014-10-16 04:43:45Z justin $
 */

#include "core/app/network.h"
#include "core/app/net/resolver.h"
#include "core/app/gui.h"
#include "core/web/browser.h"

namespace LFL {
DEFINE_int   (gui_port,            0,             "GUI Port");
DEFINE_string(resolve,             "",            "Retrieve MX and A for all domains in file");
DEFINE_string(ip_address,          "",            "Resolve from comma separated IP list; blank for all");
DECLARE_int  (target_fps);         //             Target_resolve_per_second = target_fps * frame_resolve_max 
DEFINE_int   (frame_resolve_max,   10,            "max resolve per frame");

struct BulkResolver {
  struct Query {
    bool Adone;
    string domain;
    DNS::Response A, MX;
    BulkResolver *parent;
    Query(const string &q, BulkResolver *p) : Adone(0), domain(q), parent(p) {}

    void Run() {
      RecursiveResolver::Request *req = new RecursiveResolver::Request
        (domain, Adone ? DNS::Type::MX : DNS::Type::A, 
         Resolver::ResponseCB(bind(&BulkResolver::Query::ResponseCB, this, _1, _2)));
      INFO("BulkResolver Run domain=", domain, ", type=", req->type);
      parent->rr->StartResolveRequest(req);
    }

    void Output() {
      set<IPV4::Addr> Aa;
      for (int i = 0; i < A.A.size(); i++) Aa.insert(A.A[i].addr);
      string ret = StrCat("A=", domain, ":", IPV4::MakeCSV(Aa));
      DNS::AnswerMap MXe;
      DNS::MakeAnswerMap(MX.E, &MXe);
      map<int, pair<string, string> > MXa;
      for (int i = 0; i < MX.A.size(); ++i) {
        const DNS::Record &a = MX.A[i];
        if (a.type != DNS::Type::MX) continue;
        DNS::AnswerMap::const_iterator e_iter = MXe.find(a.answer);
        if (a.question.empty() || a.answer.empty() || e_iter == MXe.end()) { ERROR("missing ", a.answer); continue; }
        MXa[a.pref] = pair<string, string>(e_iter->first, IPV4::MakeCSV(e_iter->second));
      }
      for (auto i = MXa.begin(); i != MXa.end(); ++i) {
        string hn = i->second.first;
        if (SuffixMatch(hn, ".")) hn.erase(hn.size()-1);
        StrAppend(&ret, "; MX", i->first, "=", hn, ":", i->second.second);
      }
      ret += "\n";
      if (parent->out) parent->out->WriteString(ret);
    }

    void ResponseCB(IPV4::Addr addr, DNS::Response *res) {
      bool resolved = (addr != -1 && res);
      if (!resolved) ERROR("failed to resolve: ", domain, " type=", Adone ? "MX" : "A");
      if (resolved && !Adone) A  = *res;
      if (resolved &&  Adone) MX = *res;
      if (Adone) Output();
      else { Adone=1; Run(); }
    }
  };

  vector<Query*> queue, done;
  File *out=0;
  RecursiveResolver *rr=0;
  int min_rr_completed=0;

  void OpenLog(const string &fn) {
    if (LocalFile(fn, "r").Opened()) FATAL(fn, " already exists");
    out = new LocalFile(fn, "w");
  }

  void AddQueriesFromFile(const string &fn) {
    int start_size = queue.size();
    LocalFile file(fn, "r");
    NextRecordReader nr(&file);
    for (const char *line = nr.NextLine(); line; line = nr.NextLine()) {
      queue.push_back(new Query(tolower(line), this)); 
    }
    INFO("Added ", queue.size() - start_size, " from ", fn); 
  }

  void Frame() {
    SocketService *udp_client = app->net->udp_client.get();
    if (!queue.size() || rr->queries_completed < min_rr_completed) return;
    for (int i = 0; i < FLAGS_frame_resolve_max && queue.size() && udp_client->connect_src_pool->Available(); i++) {
      Query *q = queue.back();
      queue.pop_back();
      done.push_back(q);
      q->Run();
    }
  }

  string StatsLine() const { return rr ? StrCat(", RR=", rr->queries_completed, "/", rr->queries_requested) : ""; }

} bulk_resolver;

struct StatusGUI : public HTTPServer::Resource {
  HTTPServer::Response Request(Connection *c, int method, const char *url, const char *args, const char *headers, const char *postdata, int postlen) {
    return HTTPServer::Response("text/html; charset=UTF-8", "<html><h>Blaster</h><p>Version 1.0</p></html>\n");
  }
};

int Frame(LFL::Window *W, unsigned clicks, int flag) {
  if (!FLAGS_resolve.empty()) bulk_resolver.Frame();

  char buf[256];
  if (FGets(buf, sizeof(buf))) ERROR("FPS=", app->FPS(), bulk_resolver.StatsLine());
  return 0;
}

}; // namespace LFL
using namespace LFL;

extern "C" void MyAppCreate(int argc, const char* const* argv) {
  FLAGS_max_rlimit_core = FLAGS_max_rlimit_open_files = 1;
  FLAGS_enable_network = 1;
  app = new Application(argc, argv);
  app->focused = new Window();
  app->focused->frame_cb = Frame;
}

extern "C" int MyAppMain() {
  if (app->Create(__FILE__)) return -1;
  if (app->Init())           return -1;

  HTTPServer httpd(FLAGS_gui_port, false);
  if (FLAGS_gui_port) {
    httpd.AddURL("/", new StatusGUI());
    if (app->net->Enable(&httpd)) return -1;
  }

  if (FLAGS_ip_address.empty()) {
    set<IPV4::Addr> ips;
    Sniffer::GetDeviceAddressSet(&ips);
    Singleton<FlagMap>::Get()->Set("ip_address", IPV4::MakeCSV(ips));
  }

  if (!FLAGS_resolve.empty()) {
    app->net->udp_client->connect_src_pool = new IPV4EndpointPool(FLAGS_ip_address);
    RecursiveResolver *RR = app->net->recursive_resolver.get();
    RR->StartResolveRequest(new RecursiveResolver::Request("com"));
    RR->StartResolveRequest(new RecursiveResolver::Request("net"));
    RR->StartResolveRequest(new RecursiveResolver::Request("org"));
    bulk_resolver.rr = RR;
    bulk_resolver.min_rr_completed = 3;
    bulk_resolver.OpenLog("resolve.out.txt");
    bulk_resolver.AddQueriesFromFile(FLAGS_resolve);
  }

  if (!FLAGS_gui_port && FLAGS_resolve.empty()) { INFO("nothing to do"); return 0; }

  int ret = app->Main();
  ERROR("PerformanceTimers: ", Singleton<PerformanceTimers>::Get()->DebugString());
  return ret;
}
