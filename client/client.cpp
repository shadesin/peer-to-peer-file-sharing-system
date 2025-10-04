#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <iomanip>

#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <mutex>
#include <map>
#include <atomic>
#include <condition_variable>
#include <queue>
#include <fcntl.h>
#include <unistd.h>

using std::cin;
using std::cout;
using std::endl;
using std::string;
using std::stringstream;
using std::vector;
using std::ifstream;
using std::cerr;
using std::thread;
using std::mutex;
using std::map;
using std::queue;
using std::atomic;
using std::condition_variable;
using std::pair;

static vector<pair<string,int>> trackers;
static int current_tracker=-1;
static string client_ip;
static int client_port;
static mutex shared_files_mtx;
static map<string,string> shared_files; // filename -> full local path

struct DownloadStatus {
    string gid;
    string filename;
    string destpath;
    int num_pieces;
    std::atomic<int> pieces_done;
    bool completed;

    DownloadStatus():num_pieces(0),pieces_done(0),completed(false) {}

    // explicitly delete copy
    DownloadStatus(const DownloadStatus&) = delete;
    DownloadStatus& operator=(const DownloadStatus&) = delete;

    // allow move
    DownloadStatus(DownloadStatus&& other) noexcept
        : gid(std::move(other.gid)),
          filename(std::move(other.filename)),
          destpath(std::move(other.destpath)),
          num_pieces(other.num_pieces),
          pieces_done(other.pieces_done.load()),
          completed(other.completed) {}

    DownloadStatus& operator=(DownloadStatus&& other) noexcept {
        if(this!=&other) {
            gid=std::move(other.gid);
            filename=std::move(other.filename);
            destpath=std::move(other.destpath);
            num_pieces=other.num_pieces;
            pieces_done.store(other.pieces_done.load());
            completed=other.completed;
        }
        return *this;
    }
};

static map<string,DownloadStatus> downloads; // key = gid+":"+filename
static mutex downloads_mtx;



// trim helper
string trim(const string&s)
{
    size_t i=0;
    while(i<s.size()&&(s[i]==' '||s[i]=='\t'||s[i]=='\r'||s[i]=='\n'))
    {
        i++;
    }
    size_t j=s.size();
    while(j>i&&(s[j-1]==' '||s[j-1]=='\t'||s[j-1]=='\r'||s[j-1]=='\n'))
    {
        j--;
    }
    return s.substr(i,j-i);
}

// parse ip:port
bool parse_ipport(const string&s,string&ip,int&port)
{
    size_t colon=s.find(':');
    if(colon==string::npos)
    {
        return false;
    }
    ip=s.substr(0,colon);
    string ps=s.substr(colon+1);
    port=std::stoi(ps);
    return true;
}

// load tracker_info.txt
void load_tracker_info(const string&fname)
{
    ifstream in(fname);
    if(!in)
    {
        cerr<<"could not open tracker_info.txt"<<endl;
        return;
    }
    string line;
    while(std::getline(in,line))
    {
        string t=trim(line);
        if(t.size()==0)
        {
            continue;
        }
        string ip;
        int port;
        if(parse_ipport(t,ip,port))
        {
            trackers.push_back({ip,port});
        }
    }
}

// connect to tracker
int connect_to_tracker(int index)
{
    if(index<0||index>=(int)trackers.size())
    {
        return -1;
    }
    string ip=trackers[index].first;
    int port=trackers[index].second;
    int s=socket(AF_INET,SOCK_STREAM,0);
    if(s<0)
    {
        return -1;
    }
    sockaddr_in addr;
    addr.sin_family=AF_INET;
    addr.sin_port=htons(port);
    inet_pton(AF_INET,ip.c_str(),&addr.sin_addr);
    if(connect(s,(sockaddr*)&addr,sizeof(addr))<0)
    {
        close(s);
        return -1;
    }
    current_tracker=index;
    cout<<"Connected to tracker "<<ip<<":"<<port<<endl;
    return s;
}

// try all trackers
int try_connect_any()
{
    for(size_t i=0;i<trackers.size();i++)
    {
        int s=connect_to_tracker((int)i);
        if(s>=0)
        {
            return s;
        }
    }
    return -1;
}

// peer listener
void peer_listener(const string&ip,int port)
{
    int s=socket(AF_INET,SOCK_STREAM,0);
    if(s<0)
    {
        perror("peer socket");
        return;
    }
    int opt=1;
    setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
    sockaddr_in addr;
    addr.sin_family=AF_INET;
    addr.sin_port=htons(port);
    inet_pton(AF_INET,ip.c_str(),&addr.sin_addr);
    if(::bind(s,(sockaddr*)&addr,sizeof(addr))<0)
    {
        perror("peer bind");
        close(s);
        return;
    }
    if(listen(s,5)<0)
    {
        perror("peer listen");
        close(s);
        return;
    }
    cout<<"[Client] Peer listener started on "<<ip<<":"<<port<<endl;
    while(true)
    {
        sockaddr_in cli;
        socklen_t len=sizeof(cli);
        int cs=accept(s,(sockaddr*)&cli,&len);
        if(cs<0)
        {
            continue;
        }
        thread t(
            [](int csock)
            {
                const int BUF=4096;
                char buf[BUF];
                string acc;
                // read a single request line (terminated by '\n')
                while(true)
                {
                    ssize_t r=recv(csock,buf,BUF,0);
                    if(r<=0)
                    {
                        close(csock);
                        return;
                    }
                    acc.append(buf,(size_t)r);
                    size_t pos=acc.find('\n');
                    if(pos!=string::npos)
                    {
                        string line=acc.substr(0,pos);
                        // parse by finding last space (piece_index is last token)
                        // format: GET <filename> <piece_index>\n
                        // ensure starts with GET
                        if(line.rfind("GET ",0)!=0)
                        {
                            close(csock);
                            return;
                        }
                        string payload=line.substr(4); // after "GET "
                        size_t lastsp=payload.find_last_of(' ');
                        if(lastsp==string::npos)
                        {
                            close(csock);
                            return;
                        }
                        string piece_str=payload.substr(lastsp+1);
                        int piece_index=atoi(piece_str.c_str());
                        string filename=payload.substr(0,lastsp);
                        // if filename quoted, strip quotes
                        filename=trim(filename);
                        if(filename.size()>1)
                        {
                            if((filename.front()=='"'&&filename.back()=='"')||(filename.front()=='\''&&filename.back()=='\''))
                            {
                                filename=filename.substr(1,filename.size()-2);
                            }
                        }
                        // lookup local path
                        string localpath;
                        {
                            std::lock_guard<std::mutex>lk(shared_files_mtx);
                            auto it=shared_files.find(filename);
                            if(it==shared_files.end())
                            {
                                // send zero length -> indicates error/not found
                                uint32_t z=0;
                                uint32_t nz=htonl(z);
                                send(csock,(char*)&nz,sizeof(nz),0);
                                close(csock);
                                return;
                            }
                            localpath=it->second;
                        }
                        // open and read piece
                        FILE*fp=fopen(localpath.c_str(),"rb");
                        if(fp==NULL)
                        {
                            uint32_t z=0;
                            uint32_t nz=htonl(z);
                            send(csock,(char*)&nz,sizeof(nz),0);
                            close(csock);
                            return;
                        }
                        const uint32_t PIECE_SIZE=512*1024;
                        uint64_t offset=(uint64_t)piece_index*(uint64_t)PIECE_SIZE;
                        if(fseeko(fp,(off_t)offset,SEEK_SET)!=0)
                        {
                            fclose(fp);
                            uint32_t z=0;
                            uint32_t nz=htonl(z);
                            send(csock,(char*)&nz,sizeof(nz),0);
                            close(csock);
                            return;
                        }
                        // read up to PIECE_SIZE
                        std::vector<char>chunk;
                        chunk.resize(PIECE_SIZE);
                        size_t got=fread(chunk.data(),1,PIECE_SIZE,fp);
                        fclose(fp);
                        if(got==0)
                        {
                            uint32_t z=0;
                            uint32_t nz=htonl(z);
                            send(csock,(char*)&nz,sizeof(nz),0);
                            close(csock);
                            return;
                        }
                        uint32_t n=(uint32_t)got;
                        uint32_t nn=htonl(n);
                        // send 4-byte length then data
                        ssize_t w=send(csock,(char*)&nn,sizeof(nn),0);
                        if(w!=sizeof(nn))
                        {
                            close(csock);
                            return;
                        }
                        const char*ptr=chunk.data();
                        size_t left=n;
                        while(left>0)
                        {
                            ssize_t ssend=send(csock,ptr,left,0);
                            if(ssend<=0)
                            {
                                break;
                            }
                            left-=(size_t)ssend;
                            ptr+=ssend;
                        }
                        close(csock);
                        return;
                    }
                }
            }
        ,cs);
        t.detach();
    }
}

// compute sha1 of buffer
string sha1_of_buffer(const unsigned char*data,size_t len)
{
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(data,len,hash);
    std::ostringstream oss;
    for(int i=0;i<SHA_DIGEST_LENGTH;i++)
    {
        oss<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)hash[i];
    }
    return oss.str();
}

// compute sha1 of entire file (in chunks)
string sha1_of_file(const string&path)
{
    ifstream in(path, std::ios::binary);
    if(!in) return "";
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    char buf[512*1024];
    while(in)
    {
        in.read(buf,sizeof(buf));
        std::streamsize got=in.gcount();
        if(got>0) SHA1_Update(&ctx,buf,got);
    }
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1_Final(hash,&ctx);
    std::ostringstream oss;
    for(int i=0;i<SHA_DIGEST_LENGTH;i++)
    {
        oss<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)hash[i];
    }
    return oss.str();
}

// returns pair(success,vector<char>data)
pair<bool,vector<char>> download_piece_from_peer(const string&peerip,int peerport,const string&filename,int piece_index)
{
    int s=socket(AF_INET,SOCK_STREAM,0);
    if(s<0)
    {
        return {false,{}};
    }
    sockaddr_in addr;
    addr.sin_family=AF_INET;
    addr.sin_port=htons(peerport);
    inet_pton(AF_INET,peerip.c_str(),&addr.sin_addr);
    if(connect(s,(sockaddr*)&addr,sizeof(addr))<0)
    {
        close(s);
        return {false,{}};
    }
    // send GET
    string req="GET \""+filename+"\" "+std::to_string(piece_index)+"\n";
    ssize_t rem=req.size();
    const char*ptr=req.c_str();
    while(rem>0)
    {
        ssize_t w=send(s,ptr,(size_t)rem,0);
        if(w<=0)
        {
            close(s);
            return {false,{}};
        }
        rem-=w;
        ptr+=w;
    }
    // read 4-byte length
    uint32_t nl=0;
    ssize_t r=recv(s,(char*)&nl,sizeof(nl),MSG_WAITALL);
    if(r!=sizeof(nl))
    {
        close(s);
        return {false,{}};
    }
    uint32_t n=ntohl(nl);
    if(n==0)
    {
        close(s);
        return {false,{}};
    }
    std::vector<char>buf;
    buf.resize(n);
    size_t left=n;
    char*bp=buf.data();
    while(left>0)
    {
        ssize_t got=recv(s,bp,left,0);
        if(got<=0)
        {
            close(s);
            return {false,{}};
        }
        left-=(size_t)got;
        bp+=got;
    }
    close(s);
    return {true,buf};
}

// reliable recv n bytes
ssize_t recv_n(int fd,char*buf,size_t n)
{
    size_t left=n;
    char*ptr=buf;
    while(left>0)
    {
        ssize_t r=recv(fd,ptr,left,0);
        if(r<=0)
        {
            return -1;
        }
        left-=r;
        ptr+=r;
    }
    return (ssize_t)n;
}

// Parallel download using a thread pool and pwrite for concurrent writes.
// returns true on success.

mutex print_mtx;

bool download_file_parallel(const vector<string>&peers,const string&gid,const string&filename,const string&destpath,int num_pieces,const string&file_hash,const vector<string>&piece_hashes,long long file_size)
{
    const uint32_t PIECE_SIZE=512*1024;
    int fd=open(destpath.c_str(),O_CREAT|O_WRONLY,0644);
    if(fd<0)
    {
        return false;
    }

    // task queue of piece indices
    std::queue<int>q;
    for(int i=0;i<num_pieces;i++)
    {
        q.push(i);
    }

    mutex q_mtx;
    atomic<int>remaining(num_pieces);
    atomic<bool>abort_flag(false);
    atomic<int>done_count(0);

    // prepare peers
    vector<pair<string,int>>peerlist;
    for(auto &p:peers)
    {
        string cip; int cport;
        if(parse_ipport(p,cip,cport))
        {
            peerlist.push_back({cip,cport});
        }
    }
    if(peerlist.empty())
    {
        close(fd);
        return false;
    }

    unsigned hc=std::thread::hardware_concurrency();
    if(hc==0) hc=4;
    unsigned pool_size=std::min<unsigned>(num_pieces,hc*2);
    if(pool_size==0) pool_size=1;

    const int MAX_TRIES_PER_PEER=3;

    // worker lambda
    auto worker=[&]()
    {
        while(true)
        {
            int piece=-1;
            {
                std::lock_guard<std::mutex>lk(q_mtx);
                if(q.empty()||abort_flag.load()) return;
                piece=q.front();
                q.pop();
            }

            bool piece_ok=false;
            // choose starting peer based on piece index (round-robin)
            size_t start=(size_t)piece % peerlist.size();
            for(size_t off=0;off<peerlist.size() && !piece_ok && !abort_flag.load();off++)
            {
                size_t pi=(start+off) % peerlist.size();
                string pip=peerlist[pi].first;
                int pport=peerlist[pi].second;

                for(int attempt=0;attempt<MAX_TRIES_PER_PEER && !piece_ok && !abort_flag.load();attempt++)
                {
                    auto pr=download_piece_from_peer(pip,pport,filename,piece);
                    if(!pr.first) continue;
                    string gh=sha1_of_buffer((unsigned char*)pr.second.data(),pr.second.size());
                    if(gh!=piece_hashes[piece]) continue;

                    // log which peer this piece came from
                    {
                        std::lock_guard<std::mutex> lock(print_mtx);
                        cout<<"Downloaded piece "<<piece<<" from "<<pip<<":"<<pport<<endl;
                    }

                    off_t offset=(off_t)piece*(off_t)PIECE_SIZE;
                    ssize_t to_write=(ssize_t)pr.second.size();
                    ssize_t wrote_total=0;
                    const char*bufptr=pr.second.data();
                    while(wrote_total<to_write)
                    {
                        ssize_t w=pwrite(fd,bufptr+wrote_total,(size_t)(to_write-wrote_total),offset+wrote_total);
                        if(w<=0){ abort_flag.store(true); break; }
                        wrote_total+=w;
                    }
                    if(abort_flag.load()) break;

                    piece_ok=true;
                    remaining--;

                    {
                        std::lock_guard<std::mutex> lock(downloads_mtx);
                        string key=""; // gid:filename
                        // NOTE: you must pass gid into download_file_parallel for this to work
                        key=gid+":"+filename;
                        auto it=downloads.find(key);
                        if(it!=downloads.end())
                        {
                            it->second.pieces_done++;
                        }
                    }

                    done_count++;
                }
            }
            if(!piece_ok)
            {
                abort_flag.store(true);
                return;
            }
        }
    };

    // spawn workers
    vector<thread>workers;
    for(unsigned i=0;i<pool_size;i++)
    {
        workers.emplace_back(worker);
    }

    for(auto &t:workers)
    {
        if(t.joinable())
        {
            t.join();
        }
    }
    close(fd);

    if(abort_flag.load())
    {
        return false;
    }

    truncate(destpath.c_str(),file_size);
    string final_hash=sha1_of_file(destpath);
    bool success=(final_hash==file_hash);
    if(success)
    {
        std::lock_guard<std::mutex> lock(downloads_mtx);
        string key=gid+":"+filename;
        auto it=downloads.find(key);
        if(it!=downloads.end())
        {
            it->second.completed=true;
        }
    }
    return success;

}



int main(int argc,char**argv)
{
    if(argc<3)
    {
        cout<<"Usage: "<<argv[0]<<" <IP>:<PORT> tracker_info.txt"<<endl;
        return 1;
    }

    // parse client ip and port
    if(!parse_ipport(argv[1],client_ip,client_port))
    {
        cerr<<"Invalid client address format. Use <IP>:<PORT>"<<endl;
        return 1;
    }

    // start peer listener
    thread pt(peer_listener,client_ip,client_port);
    pt.detach();

    // load tracker list
    string tfile=argv[2];
    load_tracker_info(tfile);
    if(trackers.size()==0)
    {
        cerr<<"no trackers in tracker_info.txt"<<endl;
        return 1;
    }

    int s=try_connect_any();
    if(s<0)
    {
        cerr<<"could not connect to any tracker"<<endl;
        return 1;
    }

    string line;
    while(true)
    {
        cout<<"> ";
        if(!std::getline(cin,line))
        {
            break;
        }
        string tline=trim(line);
        if(tline.size()==0)
        {
            continue;
        }

        if(tline=="show_downloads")
        {
            std::lock_guard<std::mutex> lock(downloads_mtx);
            for(auto &kv:downloads)
            {
                auto &ds=kv.second;
                if(ds.completed)
                {
                    cout<<"[C] "<<ds.gid<<" "<<ds.filename<<endl;
                }
                else
                {
                    int done=ds.pieces_done.load();
                    int total=ds.num_pieces;
                    int percent=(total>0)?(done*100/total):0;
                    cout<<"[D] "<<ds.gid<<" "<<ds.filename<<" "<<percent<<"%"<<endl;
                }
            }
            continue; // skip sending to tracker
        }

        if(tline.rfind("stop_share",0)==0)
        {
            stringstream ss(tline);
            string cmd,gid,fname;
            ss>>cmd>>gid>>fname;

            if(gid.empty()||fname.empty())
            {
                cout<<"ERROR invalid arguments"<<endl;
                continue;
            }

            {
                std::lock_guard<std::mutex> lk(shared_files_mtx);
                auto it=shared_files.find(fname);
                if(it!=shared_files.end())
                {
                    shared_files.erase(it);
                    cout<<"[Client] Stopped sharing "<<fname<<endl;
                }
            }

            // continue to forward this command to tracker (handled later in out=tline+"\n";)
        }


        string out;
        if(tline.rfind("upload_file",0)==0) // command starts with "upload_file"
        {
            stringstream ss(tline);
            string cmd,gid;
            ss>>cmd>>gid;

            size_t pos=tline.find(gid);
            if(pos==string::npos)
            {
                cout<<"ERROR invalid arguments"<<endl;
                continue;
            }
            pos=pos+gid.size();
            string fpath=tline.substr(pos);
            fpath=trim(fpath);

            if(fpath.size()>1)
            {
                if((fpath.front()=='"'&&fpath.back()=='"')||(fpath.front()=='\''&&fpath.back()=='\''))
                {
                    fpath=fpath.substr(1,fpath.size()-2);
                }
            }

            if(gid.empty()||fpath.empty())
            {
                cout<<"ERROR invalid arguments"<<endl;
                continue;
            }

            // extract only filename from path
            string filename=fpath;
            size_t p=fpath.find_last_of("/\\");
            if(p!=string::npos)
            {
                filename=fpath.substr(p+1);
            }

            ifstream in(fpath, std::ios::binary);
            if(!in)
            {
                cout<<"ERROR cannot open file"<<endl;
                continue;
            }

            // compute SHA1 hashes of pieces
            vector<string> piece_hashes;
            char buf[512*1024];
            while(in)
            {
                in.read(buf,sizeof(buf));
                std::streamsize got=in.gcount();
                if(got>0)
                {
                    piece_hashes.push_back(sha1_of_buffer((unsigned char*)buf,got));
                }
            }
            in.close();

            // compute SHA1 of full file
            string file_hash=sha1_of_file(fpath);
            int num_pieces=piece_hashes.size();

            //compute file size
            in.open(fpath,std::ios::binary|std::ios::ate);
            long long file_size=in.tellg();
            in.close();

            // build message to tracker
            std::ostringstream oss;
            oss<<"upload_file "<<gid<<" "<<filename<<" "<<client_ip<<":"<<client_port<<" "<<num_pieces<<" "<<file_hash<<" "<<file_size;
            for(auto &h:piece_hashes) oss<<" "<<h;
            oss<<"\n";

            out=oss.str();
        }
        else
        {
            out=tline+"\n";
        }
        ssize_t rem=out.size();
        const char*buf=out.c_str();
        while(rem>0)
        {
            ssize_t w=send(s,buf,(size_t)rem,0);
            if(w<=0)
            {
                cerr<<"tracker connection lost, retrying..."<<endl;
                close(s);
                s=try_connect_any();
                if(s<0)
                {
                    cerr<<"no tracker available"<<endl;
                    goto end;
                }
                buf=out.c_str();
                rem=out.size();
                continue;
            }
            rem-=w;
            buf+=w;
        }

        string response;
        char recvbuf[8192];
        while(true)
        {
            ssize_t r=recv(s,recvbuf,sizeof(recvbuf),0);
            if(r<=0)
            {
                cerr<<"tracker connection lost while receiving, retrying..."<<endl;
                close(s);
                s=try_connect_any();
                if(s<0)
                {
                    cerr<<"no tracker available"<<endl;
                    goto end;
                }
                // re-send the command to new tracker
                ssize_t rem2=out.size();
                const char*buf2=out.c_str();
                while(rem2>0)
                {
                    ssize_t w2=send(s,buf2,(size_t)rem2,0);
                    if(w2<=0) break;
                    rem2-=w2;
                    buf2+=w2;
                }
                // clear and retry receiving
                response.clear();
                continue;
            }
            response.append(recvbuf,(size_t)r);

            if(response.find("SUCCESS")!=string::npos || 
            response.find("ERROR")!=string::npos) {
                break;
            }
            if(r < (ssize_t)sizeof(recvbuf)) {
                break;
            }
        }
        cout<<response<<endl;

        // if this was a download_file request, process tracker metadata and perform download
        if(tline.rfind("download_file",0)==0)
        {
            // parse full tracker response we collected earlier
            stringstream ss(response);
            string line;
            int num_pieces=0;
            string file_hash;
            vector<string> piece_hashes;
            long long file_size=0;
            vector<string> peers;

            while(std::getline(ss,line))
            {
                if(line.size()==0) continue;
                stringstream ls(line);
                string tag;
                ls>>tag;
                if(tag=="PEERS")
                {
                    string addr;
                    while(ls>>addr)
                    {
                        peers.push_back(addr);
                    }
                }
                else if(tag=="NUM")
                {
                    ls>>num_pieces;
                }
                else if(tag=="FILEHASH")
                {
                    ls>>file_hash;
                }
                else if(tag=="PIECES")
                {
                    string h;
                    while(ls>>h)
                    {
                        piece_hashes.push_back(h);
                    }
                }
                else if(tag=="FILESIZE")
                {
                    ls>>file_size;
                }
            }

            if(peers.size()==0||num_pieces<=0||piece_hashes.size()==0)
            {
                cout<<"ERROR invalid metadata from tracker"<<endl;
            }
            else
            {
                // parse peers list (single peer in current design, but accept multiple by splitting spaces)

                stringstream cmdss(tline);
                string cmd,gid;
                cmdss>>cmd>>gid;

                // get the rest of the line (fname and destpath possibly with spaces)
                size_t pos=tline.find(gid);
                if(pos==string::npos)
                {
                    cout<<"ERROR invalid download command"<<endl;
                    return 0;
                }
                pos=pos+gid.size();
                string rest=trim(tline.substr(pos));

                string fname;
                string destpath;

                if(rest.size()>0 && (rest.front()=='"'||rest.front()=='\''))
                {
                    char q=rest.front();
                    size_t qend=rest.find(q,1);
                    if(qend==string::npos)
                    {
                        cout<<"ERROR invalid download command (unterminated quote)"<<endl;
                        return 0;
                    }
                    fname=rest.substr(1,qend-1);
                    if(qend+1<rest.size())
                    {
                        destpath=trim(rest.substr(qend+1));
                    }
                }
                else
                {
                    size_t sp=rest.find(' ');
                    if(sp==string::npos)
                    {
                        cout<<"ERROR invalid download command (missing destination)"<<endl;
                        return 0;
                    }
                    fname=rest.substr(0,sp);
                    destpath=trim(rest.substr(sp+1));
                }

                if(destpath.size()==0)
                {
                    size_t pos2=tline.find(fname);
                    if(pos2!=string::npos)
                    {
                        pos2+=fname.size();
                        destpath=trim(tline.substr(pos2));
                    }
                }

                if(destpath.size()==0)
                {
                    cout<<"ERROR invalid destination path"<<endl;
                }
                else
                {
                    // strip surrounding quotes if present
                    if(destpath.size()>1)
                    {
                        if((destpath.front()=='"'&&destpath.back()=='"')||(destpath.front()=='\''&&destpath.back()=='\''))
                        {
                            destpath=destpath.substr(1,destpath.size()-2);
                        }
                    }

                    {
                        std::lock_guard<std::mutex> lock(downloads_mtx);
                        string key=gid+":"+fname;
                        DownloadStatus ds;
                        ds.gid=gid;
                        ds.filename=fname;
                        ds.destpath=destpath;
                        ds.num_pieces=num_pieces;
                        downloads.insert_or_assign(key,std::move(ds));
                    }


                    bool ok=download_file_parallel(peers,gid,fname,destpath,num_pieces,file_hash,piece_hashes,file_size);

                    cout<<endl; // ensure clean separation from worker logs
                    if(ok)
                    {
                        cout<<"SUCCESS file downloaded to "<<destpath<<endl;

                        // extract filename from destpath
                        string filename=destpath;
                        size_t p=destpath.find_last_of("/\\");
                        if(p!=string::npos)
                        {
                            filename=destpath.substr(p+1);
                        }
                        {
                            std::lock_guard<std::mutex>lk(shared_files_mtx);
                            shared_files[filename]=destpath;
                        }
                        cout<<"[Client] Now sharing "<<filename<<" -> "<<destpath<<endl;
                        // notify tracker that the current client is now a seeder
                        std::ostringstream oss2;
                        oss2<<"upload_file "<<gid<<" "<<filename<<" "<<client_ip<<":"<<client_port<<" "
                            <<num_pieces<<" "<<file_hash<<" "<<file_size;
                        for(auto &h:piece_hashes) oss2<<" "<<h;
                        oss2<<"\n";

                        string upd=oss2.str();
                        ssize_t rem2=upd.size();
                        const char*buf2=upd.c_str();
                        while(rem2>0)
                        {
                            ssize_t w2=send(s,buf2,(size_t)rem2,0);
                            if(w2<=0) break;
                            rem2-=w2;
                            buf2+=w2;
                        }
                    }

                    // read tracker response for this auto-upload
                    char ubuf[1024];
                    ssize_t ur=recv(s,ubuf,sizeof(ubuf)-1,0);
                    if(ur>0)
                    {
                        ubuf[ur]=0;
                        string uresp(ubuf);
                        if(uresp.find("SUCCESS")!=string::npos)
                        {
                            cout<<"[Client] Tracker registered you as seeder"<<endl;
                        }
                        else
                        {
                            cerr<<"[Client] Seeder registration failed: "<<uresp;
                        }
                    }
                    else
                    {
                        cout<<"ERROR final file hash mismatch or download failed"<<endl;
                    }
                }
            }
        }

        // if upload_file was requested and tracker responded with SUCCESS, store local mapping
        if(tline.rfind("upload_file",0)==0)
        {
            if(strstr(recvbuf,"SUCCESS")!=NULL)
            {
                // parse filename used in the command (we extracted filename earlier)
                // rebuild filename same way we did earlier
                stringstream sss(tline);
                string cmd,gid;
                sss>>cmd>>gid;
                size_t pos=tline.find(gid);
                pos=pos+gid.size();
                string fpath=tline.substr(pos);
                fpath=trim(fpath);
                if(fpath.size()>0)
                {
                    if(fpath.front()=='"'||fpath.front()=='\'')
                    {
                        fpath=fpath.substr(1);
                    }
                }
                if(fpath.size()>0)
                {
                    if(fpath.back()=='"'||fpath.back()=='\'')
                    {
                        fpath=fpath.substr(0,fpath.size()-1);
                    }
                }

                string filename=fpath;
                size_t p=fpath.find_last_of("/\\");
                if(p!=string::npos)
                {
                    filename=fpath.substr(p+1);
                }
                {
                    std::lock_guard<std::mutex>lk(shared_files_mtx);
                    shared_files[filename]=fpath;
                }
                cout<<"[Client] Now sharing "<<filename<<" -> "<<fpath<<endl;
            }
        }
    }

end:
    close(s);
    return 0;
}