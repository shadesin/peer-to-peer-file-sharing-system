#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <atomic>

using std::cerr;
using std::cin;
using std::cout;
using std::endl;
using std::ifstream;
using std::map;
using std::mutex;
using std::ofstream;
using std::set;
using std::stringstream;
using std::string;
using std::thread;
using std::vector;

static mutex state_mtx;
static mutex session_mtx;
static mutex push_mtx;
static std::atomic<bool> running(true);
static string lockfile;

struct State
{
    map<string,string> users;// userid->password
    map<string,string> group_owner;// groupid->owner
    map<string,set<string>> group_members;// groupid->members
    map<string,vector<string>> join_requests;// groupid->pending
};

struct ClientInfo
{
    string userid;
    string ip;
    int port;
};

map<int,ClientInfo> sessions; // socket -> client info

struct FileInfo
{
    string owner; // user who uploaded
    string ip; // client IP
    int port; // client port
    string path; // filename only
    int num_pieces; // number of 512KB pieces
    string file_hash; // SHA1 hash of full file
    long long file_size; // size of full file in bytes
    vector<string> piece_hashes; // SHA1 hashes of pieces
};

map<string, vector<FileInfo>> group_files; // group_id -> list of shared files


static State global_state;
static vector<std::pair<string,int>> trackers;
static int this_tracker_index=0;
static bool stop_retry=false;
static int listen_sock=-1;


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

bool parse_ipport(const string&line,string&ip,int&port)
{
    size_t colon=line.find(':');
    if(colon==string::npos)
    {
        return false;
    }
    ip=line.substr(0,colon);
    string ps=line.substr(colon+1);
    port=std::stoi(ps);
    return true;
}

void load_tracker_info(const string&fname)
{
    ifstream in(fname);
    if(!in)
    {
        cerr<<"could not open tracker info file "<<fname<<endl;
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
        if(parse_ipport(t,ip,port)==false)
        {
            continue;
        }
        trackers.push_back({ip,port});
    }
}

string state_to_string()
{
    stringstream ss;
    state_mtx.lock();
    for(auto &p:global_state.users)
    {
        ss<<"USER "<<p.first<<" "<<p.second<<"\n";
    }
    for(auto &p:global_state.group_owner)
    {
        string gid=p.first;
        string owner=p.second;
        ss<<"GROUP "<<gid<<" "<<owner<<"\n";
        auto &members=global_state.group_members[gid];
        for(auto &m:members)
        {
            ss<<"MEMBER "<<gid<<" "<<m<<"\n";
        }
    }
    for(auto &p:global_state.join_requests)
    {
        string gid=p.first;
        for(auto &u:p.second)
        {
            ss<<"REQ "<<gid<<" "<<u<<"\n";
        }
    }
    for(auto &p:group_files)
    {
        string gid=p.first;
        for(auto &f:p.second)
        {
            ss<<"FILE "<<gid<<" "<<f.owner<<" "<<f.ip<<":"<<f.port<<" "<<f.path<<" "
            <<f.num_pieces<<" "<<f.file_hash<<" "<<f.file_size;
            for(auto &h:f.piece_hashes)
            {
                ss<<" "<<h;
            }
            ss<<"\n";
        }
    }
    state_mtx.unlock();
    return ss.str();
}

void write_sync_file()
{
    string payload=state_to_string();
    push_mtx.lock();
    ofstream out("tracker_sync.txt",std::ofstream::trunc);
    if(!out)
    {
        push_mtx.unlock();
        cerr<<"could not write tracker_sync.txt"<<endl;
        return;
    }
    out<<payload;
    out.close();
    push_mtx.unlock();
}

void apply_state_from_string(const string&payload)
{
    state_mtx.lock();
    global_state.users.clear();
    global_state.group_owner.clear();
    global_state.group_members.clear();
    global_state.join_requests.clear();
    group_files.clear();
    stringstream ss(payload);
    string line;
    while(std::getline(ss,line))
    {
        stringstream ls(line);
        string tag;
        ls>>tag;
        if(tag=="USER")
        {
            string uid,pw;
            ls>>uid>>pw;
            if(uid.size())
            {
                global_state.users[uid]=pw;
            }
        }
        else if(tag=="GROUP")
        {
            string gid,owner;
            ls>>gid>>owner;
            if(gid.size())
            {
                global_state.group_owner[gid]=owner;
            }
        }
        else if(tag=="MEMBER")
        {
            string gid,uid;
            ls>>gid>>uid;
            if(gid.size()&&uid.size())
            {
                global_state.group_members[gid].insert(uid);
            }
        }
        else if(tag=="REQ")
        {
            string gid,uid;
            ls>>gid>>uid;
            if(gid.size()&&uid.size())
            {
                global_state.join_requests[gid].push_back(uid);
            }
        }
        else if(tag=="FILE")
        {
            string gid,owner,addr,path,file_hash;
            int num_pieces;
            long long file_size;
            ls>>gid>>owner>>addr>>path>>num_pieces>>file_hash>>file_size;
            string cip; int cport;
            if(parse_ipport(addr,cip,cport))
            {
                FileInfo fi;
                fi.owner=owner;
                fi.ip=cip;
                fi.port=cport;
                fi.path=path;
                fi.num_pieces=num_pieces;
                fi.file_hash=file_hash;
                fi.file_size=file_size;
                for(int i=0;i<num_pieces;i++)
                {
                    string h; ls>>h;
                    fi.piece_hashes.push_back(h);
                }
                group_files[gid].push_back(fi);
            }
        }
    }
    state_mtx.unlock();
}

void load_sync_file()
{
    ifstream in("tracker_sync.txt");
    if(!in)
    {
        return;
    }
    string content;
    string line;
    while(std::getline(in,line))
    {
        content+=line+"\n";
    }
    if(content.size()>0)
    {
        apply_state_from_string(content);
    }
}

int push_sync_to_peer_once(const string&payload)
{
    if(trackers.size()<2)
    {
        return -1;
    }
    int peer_index=(this_tracker_index+1)%trackers.size();
    string peer_ip=trackers[peer_index].first;
    int peer_port=trackers[peer_index].second;
    int s=socket(AF_INET,SOCK_STREAM,0);
    if(s<0)
    {
        return -1;
    }
    sockaddr_in addr;
    addr.sin_family=AF_INET;
    addr.sin_port=htons(peer_port);
    inet_pton(AF_INET,peer_ip.c_str(),&addr.sin_addr);
    if(connect(s,(sockaddr*)&addr,sizeof(addr))<0)
    {
        close(s);
        return -1;
    }
    string msg="SYNC\n"+payload+"END\n";
    ssize_t rem=msg.size();
    const char*buf=msg.c_str();
    while(rem>0)
    {
        ssize_t w=send(s,buf,(size_t)rem,0);
        if(w<=0)
        {
            break;
        }
        rem-=w;
        buf+=w;
    }
    // read ack (optional)
    char ack[512];
    ssize_t r=recv(s,ack,sizeof(ack)-1,0);
    if(r>0)
    {
        ack[r]=0;
    }
    close(s);
    if(rem==0)
    {
        return 0;
    }
    return -1;
}

void retry_push_thread()
{
    while(true)
    {
        if(stop_retry==true)
        {
            break;
        }
        push_mtx.lock();
        ifstream in("tracker_sync.txt");
        if(!in)
        {
            push_mtx.unlock();
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }
        string content;
        string line;
        while(std::getline(in,line))
        {
            content+=line+"\n";
        }
        in.close();
        push_mtx.unlock();
        if(content.size()>0)
        {
            int r=push_sync_to_peer_once(content);
            if(r==0)
            {
                // success
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}


string process_command_for_conn(const string&cmd_line,int sock)
{
    cout<<"[Tracker "<<this_tracker_index+1<<"] Received from client "<<sock<<": "<<cmd_line<<endl;

    stringstream ss(cmd_line);
    string cmd;
    ss>>cmd;

    if(cmd=="create_user")
    {
        string uid,pw;
        ss>>uid>>pw;
        if(uid.size()==0||pw.size()==0)
        {
            return "ERROR invalid arguments\n";
        }
        state_mtx.lock();
        if(global_state.users.find(uid)!=global_state.users.end())
        {
            state_mtx.unlock();
            return "ERROR user exists\n";
        }
        global_state.users[uid]=pw;
        state_mtx.unlock();
        write_sync_file();
        string payload=state_to_string();
        push_sync_to_peer_once(payload);
        return "SUCCESS user created\n";
    }
    else if(cmd=="login")
    {
        string uid,pw;
        ss>>uid>>pw;
        if(uid.size()==0||pw.size()==0)
        {
            return "ERROR invalid arguments\n";
        }

        state_mtx.lock();
        auto it=global_state.users.find(uid);
        if(it==global_state.users.end())
        {
            state_mtx.unlock();
            return "ERROR no such user\n";
        }
        if(it->second!=pw)
        {
            state_mtx.unlock();
            return "ERROR wrong password\n";
        }
        state_mtx.unlock();

        // check if already logged in
        session_mtx.lock();
        for(auto &entry : sessions)
        {
            if(entry.second.userid==uid)
            {
                session_mtx.unlock();
                return "User "+uid+" already logged in\n";
            }
        }

        sessions[sock] = {uid,"",0}; // store only userid for now
        session_mtx.unlock();

        cout<<"[Tracker "<<this_tracker_index+1<<"] User "<<uid<<" logged in"<<endl;

        return "SUCCESS logged in\n";
    }


    else if(cmd=="logout")
    {
        session_mtx.lock();
        auto it=sessions.find(sock);
        if(it==sessions.end())
        {
            session_mtx.unlock();
            return "ERROR not logged in\n";
        }
        sessions.erase(it);
        session_mtx.unlock();
        return "SUCCESS logged out\n";
    }
    else if(cmd=="create_group")
    {
        session_mtx.lock();
        auto sit=sessions.find(sock);
        if(sit==sessions.end())
        {
            session_mtx.unlock();
            return "ERROR not logged in\n";
        }
        string uid=sit->second.userid;
        session_mtx.unlock();
        string gid;
        ss>>gid;
        if(gid.size()==0)
        {
            return "ERROR invalid arguments\n";
        }
        state_mtx.lock();
        if(global_state.group_owner.find(gid)!=global_state.group_owner.end())
        {
            state_mtx.unlock();
            return "ERROR group exists\n";
        }
        global_state.group_owner[gid]=uid;
        global_state.group_members[gid].insert(uid);
        state_mtx.unlock();
        write_sync_file();
        string payload=state_to_string();
        push_sync_to_peer_once(payload);
        return "SUCCESS group created\n";
    }
    else if(cmd=="join_group")
    {
        session_mtx.lock();
        auto sit=sessions.find(sock);
        if(sit==sessions.end())
        {
            session_mtx.unlock();
            return "ERROR not logged in\n";
        }
        string uid=sit->second.userid;
        session_mtx.unlock();
        string gid;
        ss>>gid;
        if(gid.size()==0)
        {
            return "ERROR invalid arguments\n";
        }
        state_mtx.lock();
        if(global_state.group_owner.find(gid)==global_state.group_owner.end())
        {
            state_mtx.unlock();
            return "ERROR no such group\n";
        }
        // if already a member
        if(global_state.group_members[gid].find(uid)!=global_state.group_members[gid].end())
        {
            state_mtx.unlock();
            return "ERROR already member\n";
        }
        global_state.join_requests[gid].push_back(uid);
        state_mtx.unlock();
        write_sync_file();
        string payload=state_to_string();
        push_sync_to_peer_once(payload);
        return "SUCCESS join request sent\n";
    }
    else if(cmd=="leave_group")
    {
        session_mtx.lock();
        auto sit=sessions.find(sock);
        if(sit==sessions.end())
        {
            session_mtx.unlock();
            return "ERROR not logged in\n";
        }
        string uid=sit->second.userid;
        session_mtx.unlock();

        string gid;
        ss>>gid;
        if(gid.size()==0)
        {
            return "ERROR invalid arguments\n";
        }

        state_mtx.lock();

        // Check if user is the group owner
        auto go=global_state.group_owner.find(gid);
        if(go!=global_state.group_owner.end() && go->second==uid)
        {
            state_mtx.unlock();
            return "ERROR group owner cannot leave the group\n";
        }

        if(global_state.group_members.find(gid)!=global_state.group_members.end())
        {
            global_state.group_members[gid].erase(uid);
        }

        // purge this user's files from this group
        auto it=group_files.find(gid);
        if(it!=group_files.end())
        {
            auto &vec=it->second;
            vec.erase(
                std::remove_if(vec.begin(),vec.end(),
                    [&](const FileInfo&f){ return f.owner==uid; }),
                vec.end()
            );
        }

        state_mtx.unlock();
        write_sync_file();
        string payload=state_to_string();
        push_sync_to_peer_once(payload);
        return "SUCCESS left group\n";
    }


    else if(cmd=="list_groups")
    {
        state_mtx.lock();
        stringstream out;
        for(auto &p:global_state.group_owner)
        {
            out<<p.first<<"\n";
        }
        state_mtx.unlock();
        return "GROUPS\n"+out.str();
    }
    else if(cmd=="list_requests")
    {
        session_mtx.lock();
        auto sit=sessions.find(sock);
        if(sit==sessions.end())
        {
            session_mtx.unlock();
            return "ERROR not logged in\n";
        }
        string uid=sit->second.userid;
        session_mtx.unlock();

        string gid;
        ss>>gid;
        if(gid.size()==0)
        {
            return "ERROR invalid arguments\n";
        }

        state_mtx.lock();
        auto go=global_state.group_owner.find(gid);
        if(go==global_state.group_owner.end())
        {
            state_mtx.unlock();
            return "ERROR no such group\n";
        }
        if(go->second!=uid)
        {
            state_mtx.unlock();
            return "ERROR only group owner can view join requests\n";
        }

        stringstream out;
        auto it=global_state.join_requests.find(gid);
        if(it!=global_state.join_requests.end())
        {
            for(auto &u:it->second)
            {
                out<<u<<"\n";
            }
        }
        state_mtx.unlock();
        return "REQUESTS\n"+out.str();
    }

    else if(cmd=="accept_request")
    {
        session_mtx.lock();
        auto sit=sessions.find(sock);
        if(sit==sessions.end())
        {
            session_mtx.unlock();
            return "ERROR not logged in\n";
        }
        string uid=sit->second.userid;
        session_mtx.unlock();
        string gid,req_user;
        ss>>gid>>req_user;
        if(gid.size()==0||req_user.size()==0)
        {
            return "ERROR invalid arguments\n";
        }
        state_mtx.lock();
        auto go=global_state.group_owner.find(gid);
        if(go==global_state.group_owner.end())
        {
            state_mtx.unlock();
            return "ERROR no such group\n";
        }
        if(go->second!=uid)
        {
            state_mtx.unlock();
            return "ERROR not group owner\n";
        }
        auto &vec=global_state.join_requests[gid];
        bool found=false;
        for(size_t i=0;i<vec.size();i++)
        {
            if(vec[i]==req_user)
            {
                vec.erase(vec.begin()+i);
                found=true;
                break;
            }
        }
        if(found==true)
        {
            global_state.group_members[gid].insert(req_user);
        }
        state_mtx.unlock();
        write_sync_file();
        string payload=state_to_string();
        push_sync_to_peer_once(payload);
        if(found==true)
        {
            return "SUCCESS request accepted\n";
        }
        else
        {
            return "ERROR request not found\n";
        }
    }
    else if(cmd=="upload_file")
    {
        session_mtx.lock();
        auto sit=sessions.find(sock);
        if(sit==sessions.end())
        {
            session_mtx.unlock();
            return "ERROR not logged in\n";
        }
        string uid=sit->second.userid;
        session_mtx.unlock();

        string gid;
        ss>>gid;

        string token;
        string fpath;
        string addr;
        int num_pieces=0;
        string file_hash;
        long long file_size=0;
        bool addr_found=false;

        // collect filename tokens until we see ip:port
        while(ss>>token)
        {
            if(token.find(':')!=string::npos) // ip:port found
            {
                addr=token;
                ss>>num_pieces>>file_hash>>file_size;
                addr_found=true;
                break;
            }
            else
            {
                if(!fpath.empty())
                {
                    fpath=fpath+" ";
                }
                fpath=fpath+token;
            }
        }

        if(gid.size()==0||fpath.size()==0||addr_found==false||num_pieces<=0||file_hash.size()==0)
        {
            return "ERROR invalid arguments\n";
        }

        string cip; int cport;
        if(!parse_ipport(addr,cip,cport))
        {
            return "ERROR invalid client address\n";
        }

        vector<string> piece_hashes;
        for(int i=0;i<num_pieces;i++)
        {
            string h; ss>>h;
            piece_hashes.push_back(h);
        }

        state_mtx.lock();
        if(global_state.group_owner.find(gid)==global_state.group_owner.end())
        {
            state_mtx.unlock();
            return "ERROR no such group\n";
        }
        if(global_state.group_members[gid].find(uid)==global_state.group_members[gid].end())
        {
            state_mtx.unlock();
            return "ERROR not a group member\n";
        }

        // allow multiple seeders: only block if same user already registered this file
        bool exists=false;
        for(auto &f:group_files[gid])
        {
            if(f.file_hash==file_hash && f.owner==uid)
            {
                exists=true;
                break;
            }
        }

        if(exists)
        {
            state_mtx.unlock();
            return "ERROR you already uploaded this file\n";
        }

        FileInfo fi;
        fi.owner=uid;
        fi.ip=cip;
        fi.port=cport;
        fi.path=fpath;
        fi.num_pieces=num_pieces;
        fi.file_hash=file_hash;
        fi.file_size=file_size;
        fi.piece_hashes=piece_hashes;
        group_files[gid].push_back(fi);

        state_mtx.unlock();

        write_sync_file();
        string payload=state_to_string();
        push_sync_to_peer_once(payload);

        cout<<"[Tracker "<<this_tracker_index+1<<"] User "<<uid<<" uploaded file "<<fpath<<" to group "<<gid<<endl;

        return "SUCCESS file uploaded\n";
    }
    else if(cmd=="stop_share")
    {
        session_mtx.lock();
        auto sit=sessions.find(sock);
        if(sit==sessions.end())
        {
            session_mtx.unlock();
            return "ERROR not logged in\n";
        }
        string uid=sit->second.userid;
        session_mtx.unlock();

        string gid,fname;
        ss>>gid>>fname;
        if(gid.empty()||fname.empty())
        {
            return "ERROR invalid arguments\n";
        }

        state_mtx.lock();
        // check membership
        if(global_state.group_members[gid].find(uid)==global_state.group_members[gid].end())
        {
            state_mtx.unlock();
            return "ERROR not a group member\n";
        }

        // erase only this user's file entry
        auto it=group_files.find(gid);
        if(it!=group_files.end())
        {
            auto &vec=it->second;
            size_t before=vec.size();
            vec.erase(
                std::remove_if(vec.begin(),vec.end(),
                    [&](const FileInfo&f){ return f.owner==uid && f.path==fname; }),
                vec.end()
            );
            if(vec.size()<before)
            {
                state_mtx.unlock();
                write_sync_file();
                string payload=state_to_string();
                push_sync_to_peer_once(payload);
                return "SUCCESS stopped sharing file\n";
            }
        }
        state_mtx.unlock();
        return "ERROR file not found or not owned by you\n";
    }
    else if(cmd=="list_files")
    {
        session_mtx.lock();
        auto sit=sessions.find(sock);
        if(sit==sessions.end())
        {
            session_mtx.unlock();
            return "ERROR not logged in\n";
        }
        string uid=sit->second.userid;
        session_mtx.unlock();

        string gid;
        ss>>gid;
        if(gid.size()==0)
        {
            return "ERROR invalid arguments\n";
        }

        state_mtx.lock();
        // check if group exists
        if(global_state.group_owner.find(gid)==global_state.group_owner.end())
        {
            state_mtx.unlock();
            return "ERROR no such group\n";
        }

        // check if user is a member
        if(global_state.group_members[gid].find(uid)==global_state.group_members[gid].end())
        {
            state_mtx.unlock();
            return "ERROR not a group member\n";
        }

        stringstream out;
        auto it=group_files.find(gid);
        if(it!=group_files.end())
        {
            for(auto &f:it->second)
            {
                out<<f.path<<" (owner: "<<f.owner<<")\n";
            }
        }
        state_mtx.unlock();

        return "FILES\n"+out.str();
    }
    else if(cmd=="download_file")
    {
        session_mtx.lock();
        auto sit=sessions.find(sock);
        if(sit==sessions.end())
        {
            session_mtx.unlock();
            return "ERROR not logged in\n";
        }
        string uid=sit->second.userid;
        session_mtx.unlock();

        string gid;
        ss>>gid;

        // get rest of line as filename (may contain spaces or quotes)
        // get rest of line (filename + maybe destination)
        string rest;
        getline(ss,rest);
        rest=trim(rest);

        // split rest: first token is filename (may be quoted)
        string fname;
        if(rest.size()>0 && (rest.front()=='"'||rest.front()=='\''))
        {
            char q=rest.front();
            size_t qend=rest.find(q,1);
            if(qend!=string::npos)
            {
                fname=rest.substr(1,qend-1);
            }
        }
        else
        {
            size_t sp=rest.find(' ');
            if(sp!=string::npos)
            {
                fname=rest.substr(0,sp);
            }
            else
            {
                fname=rest;
            }
        }


        if(gid.size()==0||fname.size()==0)
        {
            return "ERROR invalid arguments\n";
        }

        state_mtx.lock();
        if(global_state.group_owner.find(gid)==global_state.group_owner.end())
        {
            state_mtx.unlock();
            return "ERROR no such group\n";
        }
        if(global_state.group_members[gid].find(uid)==global_state.group_members[gid].end())
        {
            state_mtx.unlock();
            return "ERROR not a group member\n";
        }

        auto it=group_files.find(gid);
        if(it==group_files.end())
        {
            state_mtx.unlock();
            return "ERROR no files in this group\n";
        }

        vector<FileInfo> matches;
        for(auto &f:it->second)
        {
            if(f.path==fname)
            {
                // check if this owner is currently logged in
                bool logged_in=false;
                session_mtx.lock();
                for(auto &s:sessions)
                {
                    if(s.second.userid==f.owner)
                    {
                        logged_in=true;
                        break;
                    }
                }
                session_mtx.unlock();

                if(logged_in)
                {
                    matches.push_back(f);
                }
            }
        }
        if(matches.empty())
        {
            state_mtx.unlock();
            return "ERROR file not found\n";
        }

        // use the first file entry to get metadata (hashes, num_pieces, file_size)
        FileInfo target=matches[0];

        stringstream out;
        out<<"PEERS";
        for(auto &f:matches)
        {
            out<<" "<<f.ip<<":"<<f.port;
        }
        out<<"\n";
        out<<"NUM "<<target.num_pieces<<"\n";
        out<<"FILEHASH "<<target.file_hash<<"\n";
        out<<"FILESIZE "<<target.file_size<<"\n";
        out<<"PIECES";
        for(auto &h:target.piece_hashes)
        {
            out<<" "<<h;
        }
        out<<"\n";

        state_mtx.unlock();
        return out.str();
    }
    else if(cmd=="SYNC")
    {
        // full payload follows after newline; in our socket handling we already assemble entire payload
        // here treat remainder of cmd_line as payload
        size_t pos=cmd_line.find('\n');
        string payload;
        if(pos!=string::npos)
        {
            payload=cmd_line.substr(pos+1);
        }
        if(payload.size()>0)
        {
            apply_state_from_string(payload);
            write_sync_file();
            return "SUCCESS sync applied\n";
        }
        return "ERROR invalid sync\n";
    }
    return "ERROR unknown command\n";
}

void handle_connection(int client_sock)
{
    const int BUF=4096;
    char buffer[BUF];
    string acc;
    while(running)
    {
        ssize_t r=recv(client_sock,buffer,BUF,0);
        if(r<=0)
        {
            break;
        }
        acc.append(buffer,(size_t)r);
        while(true)
        {
            size_t pos=acc.find('\n');
            if(pos==string::npos)
            {
                break;
            }
            string line=acc.substr(0,pos);
            acc.erase(0,pos+1);
            string tline=trim(line);
            if(tline.size()==0)
            {
                continue;
            }
            if(tline=="SYNC")
            {
                string payload;
                while(true)
                {
                    size_t pos2=acc.find("\nEND\n");
                    if(pos2!=string::npos)
                    {
                        payload+=acc.substr(0,pos2);
                        acc.erase(0,pos2+5);
                        break;
                    }
                    ssize_t r2=recv(client_sock,buffer,BUF,0);
                    if(r2<=0)
                    {
                        break;
                    }
                    acc.append(buffer,(size_t)r2);
                }
                if(payload.size()>0)
                {
                    apply_state_from_string(payload);
                    write_sync_file();
                    string resp="SUCCESS sync applied\n";
                    send(client_sock,resp.c_str(),(size_t)resp.size(),0);
                }
                continue;
            }
            string resp=process_command_for_conn(tline,client_sock);
            send(client_sock,resp.c_str(),(size_t)resp.size(),0);
        }
    }
    session_mtx.lock();
    auto it=sessions.find(client_sock);
    if(it!=sessions.end())
    {
        string uid=it->second.userid;
        sessions.erase(it);
        session_mtx.unlock();

        cout<<"[Tracker "<<this_tracker_index+1<<"] User "<<uid<<" disconnected, session ended"<<endl;
    }
    else
    {
        session_mtx.unlock();
    }
    close(client_sock);

}

int make_listen_socket(const string&ip,int port)
{
    int s=socket(AF_INET,SOCK_STREAM,0);
    if(s<0)
    {
        perror("socket");
        return -1;
    }
    int opt=1;
    setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
    sockaddr_in addr;
    addr.sin_family=AF_INET;
    addr.sin_port=htons(port);
    inet_pton(AF_INET,ip.c_str(),&addr.sin_addr);
    if(::bind(s,(sockaddr*)&addr,sizeof(addr))<0)
    {
        perror("bind");
        close(s);
        return -1;
    }
    if(listen(s,10)<0)
    {
        perror("listen");
        close(s);
        return -1;
    }
    return s;
}

void console_thread()
{
    string line;
    while(true)
    {
        if(!getline(cin,line))
        {
            break;
        }
        if(trim(line)=="quit")
        {
            cout<<"[Tracker "<<this_tracker_index+1<<"] Shutdown requested from console"<<endl;
            running=false;
            if(listen_sock!=-1)
            {
                shutdown(listen_sock,SHUT_RDWR);
                close(listen_sock);
                listen_sock=-1;
            }
            break;
        }
    }
}

int main(int argc,char**argv)
{
    if(argc<3)
    {
        cout<<"Usage: "<<argv[0]<<" tracker_info.txt <tracker_no(1|2)>"<<endl;
        return 1;
    }
    string tfile=argv[1];
    this_tracker_index=atoi(argv[2])-1;
    load_tracker_info(tfile);

    // create a lock file for this tracker
    lockfile = "tracker" + std::to_string(this_tracker_index+1) + ".lock";
    {
        std::ofstream lf(lockfile);
        lf << "running";
    }

    if(this_tracker_index<0||this_tracker_index>=(int)trackers.size())
    {
        cerr<<"invalid tracker index"<<endl;
        return 1;
    }
    load_sync_file();
    thread retryt(retry_push_thread);
    retryt.detach();

    thread console(console_thread);
    console.detach();

    string bind_ip=trackers[this_tracker_index].first;
    int bind_port=trackers[this_tracker_index].second;
    listen_sock=make_listen_socket(bind_ip,bind_port);
    if(listen_sock<0)
    {
        cerr<<"failed to create listen socket"<<endl;
        stop_retry=true;
        return 1;
    }
    cout<<"Tracker listening on "<<bind_ip<<":"<<bind_port<<endl;

    while(running)
    {
        sockaddr_in cli;
        socklen_t len=sizeof(cli);
        int cs=accept(listen_sock,(sockaddr*)&cli,&len);
        if(cs<0)
        {
            if(!running) break;
            continue;
        }
        thread t(handle_connection,cs);
        t.detach();
    }
    close(listen_sock);
    stop_retry=true;
    cout<<"[Tracker "<<this_tracker_index+1<<"] Exiting"<<endl;

    // remove this tracker's lock file (we still keep creating locks on startup; remove ours now)
    remove(lockfile.c_str());

    // If there are other trackers configured, check whether any other tracker is actually listening.
    // Only delete tracker_sync.txt if no other tracker responds.
    bool other_alive=false;
    if(trackers.size()>=2)
    {
        for(size_t i=0;i<trackers.size();i++)
        {
            if((int)i==this_tracker_index)
            {
                continue;
            }
            string tip=trackers[i].first;
            int tport=trackers[i].second;

            int psock=socket(AF_INET,SOCK_STREAM,0);
            if(psock<0)
            {
                continue;
            }

            // set non-blocking so connect won't hang for long
            int flags=fcntl(psock,F_GETFL,0);
            if(flags!=-1)
            {
                fcntl(psock,F_SETFL,flags|O_NONBLOCK);
            }

            sockaddr_in peer;
            peer.sin_family=AF_INET;
            peer.sin_port=htons(tport);
            inet_pton(AF_INET,tip.c_str(),&peer.sin_addr);

            int cres=connect(psock,(sockaddr*)&peer,sizeof(peer));
            if(cres==0)
            {
                // immediate connect success -> other tracker alive
                other_alive=true;
                close(psock);
                break;
            }
            else
            {
                if(errno==EINPROGRESS || errno==EWOULDBLOCK)
                {
                    fd_set wf;
                    FD_ZERO(&wf);
                    FD_SET(psock,&wf);
                    struct timeval tv;
                    tv.tv_sec=1; // 1 second timeout
                    tv.tv_usec=0;
                    int sel=select(psock+1,NULL,&wf,NULL,&tv);
                    if(sel>0 && FD_ISSET(psock,&wf))
                    {
                        int err=0;
                        socklen_t elen=sizeof(err);
                        if(getsockopt(psock,SOL_SOCKET,SO_ERROR,&err,&elen)==0 && err==0)
                        {
                            other_alive=true;
                            close(psock);
                            break;
                        }
                    }
                }
            }
            close(psock);
        }
    }

    // If no other tracker responded, safe to delete the synced file
    if(!other_alive)
    {
        remove("tracker_sync.txt");
    }

    return 0;
}