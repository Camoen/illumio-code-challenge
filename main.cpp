#include <string>
#include <iostream>
#include <fstream>
#include <queue>
#include <unordered_map>
#include <unordered_set>
using namespace std;


// Parse IP addresses into double format
double parseIP(string ip) {
	double result = 0;
	size_t ind = ip.find(".");
	int run = 0;
	while (ind != string::npos) {
		result *= 1000;
		result += stoi(ip.substr(0, ind));
		// If analyzing the 2nd or 3rd octet
		if (run > 0 && run < 2) {
			// If octet is less than 3 digits, pad with zeroes
			if (ind == 0) {
				result *= 1000;
			} else if (ind == 1) {
				result *= 100;
			} else if (ind == 2) {
				result *= 10;
			}
		}
		run++;
		ind = ip.find(".");
		if (ind == string::npos) {
			break;
		}
		ip = ip.substr(ind + 1);
	}

	return result;
}

// Comparator for IP range priority queue
class Compare {
public:
	bool operator() (pair<double, double> p1, pair<double, double> p2) {
		// Smallest ranges appear earlier in the queue (will be reversed when stored in vectors)
		// The goal is to check larger ranges first
		return p1.second - p1.first < p2.second - p2.first;
	}
};

class Firewall {
public:
	// Sets of port numbers (hash tables for O(1) look up)
	unordered_set<int> tcp_in;
	unordered_set<int> tcp_out;
	unordered_set<int> udp_in;
	unordered_set<int> udp_out;

	// Sets for single IP Addresses
	unordered_set<string> tcp_ip_in;
	unordered_set<string> tcp_ip_out;
	unordered_set<string> udp_ip_in;
	unordered_set<string> udp_ip_out;

	// Priority Queue pairs for IP Address ranges
	// O(log n) lookup with binary search, but this requires the combination of overlapping ranges
	// O(n) lookup if I prioritize by largest range and check linearly
	priority_queue<pair<double, double>, vector<pair<double, double>>, Compare> tcp_ips_in;
	priority_queue<pair<double, double>, vector<pair<double, double>>, Compare> tcp_ips_out;
	priority_queue<pair<double, double>, vector<pair<double, double>>, Compare> udp_ips_in;
	priority_queue<pair<double, double>, vector<pair<double, double>>, Compare> udp_ips_out;

	// Vectors to hold priority queue data (for iteration)
	vector<pair<double, double>> tcp_in_range;
	vector<pair<double, double>> tcp_out_range;
	vector<pair<double, double>> udp_in_range;
	vector<pair<double, double>> udp_out_range;

	bool accept_packet(string direction, string protocol, int port, string ip);

	// Constructor (with parameter)
	Firewall(string filepath) {
		// Read in the firewall rules
		string line;
		ifstream rule_file(filepath);
		if (rule_file.is_open()) {
			while (getline(rule_file, line)) {
				// Get direction and protocol
				bool inbound = false;
				bool tcp = false;
				size_t ind = line.find("inbound");
				if (ind != string::npos) {
					inbound = true;
				}
				ind = line.find("tcp");
				if (ind != string::npos) {
					tcp = true;
				}
				else {
					ind = line.find("udp");
				}

				// Handle ports (since max range is 65535, hashing is viable)
				string port = line.substr(ind + 4);
				ind = port.find(",");
				size_t hyphen = port.find("-");
				// Check for port ranges
				if (hyphen == string::npos || hyphen > ind) {
					int portnum = stoi(port.substr(0, ind));
					// Insert port number into the correct set
					if (inbound) {
						if (tcp) {
							tcp_in.insert(portnum);
						}
						else {
							udp_in.insert(portnum);
						}
					}
					else {
						if (tcp) {
							tcp_out.insert(portnum);
						}
						else {
							udp_out.insert(portnum);
						}
					}
				} // Deal with ranges of ports
				else {
					// Insert range of port numbers into the correct set
					int low = stoi(port.substr(0, hyphen));
					int high = stoi(port.substr(hyphen+1,ind-hyphen-1));
					for (int i = low; i <= high; i++) {
						if (inbound) {
							if (tcp) {
								tcp_in.insert(i);
							}
							else {
								udp_in.insert(i);
							}
						}
						else {
							if (tcp) {
								tcp_out.insert(i);
							}
							else {
								udp_out.insert(i);
							}
						}
					}
				}

				// Handle IP Addresses
				string ip = port.substr(ind + 1);
				// Check if range of IP Addresses or single IP Address
				ind = ip.find("-");
				if (ind == string::npos) {
					// Insert single IP Address into correct set
					if (inbound) {
						if (tcp) {
							tcp_ip_in.insert(ip);
						}
						else {
							udp_ip_in.insert(ip);
						}
					}
					else {
						if (tcp) {
							tcp_ip_out.insert(ip);
						}
						else {
							udp_ip_out.insert(ip);
						}
					}
				}  // Deal with IP ranges
				else {
					double ip1 = parseIP(ip.substr(0, ind));
					double ip2 = parseIP(ip.substr(ind + 1));
					// Insert IP Address range into correct priority queue
					if (inbound) {
						if (tcp) {
							tcp_ips_in.push(make_pair(ip1, ip2));
						}
						else {
							udp_ips_in.push(make_pair(ip1, ip2));
						}
					}
					else {
						if (tcp) {
							tcp_ips_out.push(make_pair(ip1, ip2));
						}
						else {
							udp_ips_out.push(make_pair(ip1, ip2));
						}
					}
				}
			}
		}
		rule_file.close();

		// Store priority queue results in vectors for iteration (INEFFICIENT--see README for explanation)
		while (!tcp_ips_in.empty()) {
			tcp_in_range.push_back(tcp_ips_in.top());
			tcp_ips_in.pop();
		}
		while (!tcp_ips_out.empty()) {
			tcp_out_range.push_back(tcp_ips_out.top());
			tcp_ips_out.pop();
		}
		while (!udp_ips_in.empty()) {
			udp_in_range.push_back(udp_ips_in.top());
			udp_ips_in.pop();
		}
		while (!udp_ips_out.empty()) {
			udp_out_range.push_back(udp_ips_out.top());
			udp_ips_out.pop();
		}
	}

};

bool Firewall::accept_packet(string direction, string protocol, int port, string ip) {
	bool in = false;
	bool out = false;
	bool tcp = false;
	bool udp = false;

	// Check direction
	if (direction == "inbound") {
		in = true;
	}
	else if (direction == "outbound") {
		out = true;
	}
	else {
		return false;
	}

	// Check protocol
	if (protocol == "tcp") {
		tcp = true;
	}
	else if (protocol == "udp") {
		udp = true;
	}
	else {
		return false;
	}

	// Check port number in the correct set (direction & protocol combination)
	if (tcp && in) {
		auto itr = tcp_in.find(port);
		if (itr == tcp_in.end()) {
			return false;
		}
	}
	else if (tcp && out) {
		auto itr = tcp_out.find(port);
		if (itr == tcp_out.end()) {
			return false;
		}
	}
	else if (udp && in) {
		auto itr = udp_in.find(port);
		if (itr == udp_in.end()) {
			return false;
		}
	}
	else if (udp && out) {
		auto itr = udp_out.find(port);
		if (itr == udp_out.end()) {
			return false;
		}
	}

	// Check IP in the correct set (direction & protocol combination)
	if (tcp && in) {
		auto itr = tcp_ip_in.find(ip);
		// If not in the set containing all single IP Addresses, check ranges
		if (itr == tcp_ip_in.end()) {
			// parse the IP from string to double
			double numIP = parseIP(ip);
			// For each range, check if the IP is within it
			for (unsigned int i = 0; i < tcp_in_range.size(); i++) {
				if (numIP >= tcp_in_range[i].first && numIP <= tcp_in_range[i].second) {
					return true;
				}
			}
			// If the IP address didn't appear in any given range, return false
			return false;
		}
	}
	else if (tcp && out) {
		auto itr = tcp_ip_out.find(ip);
		if (itr == tcp_ip_out.end()) {
			double numIP = parseIP(ip);
			for (unsigned int i = 0; i < tcp_out_range.size(); i++) {
				if (numIP >= tcp_out_range[i].first && numIP <= tcp_out_range[i].second) {
					return true;
				}
			}
			return false;
		}
	}
	else if (udp && in) {
		auto itr = udp_ip_in.find(ip);
		if (itr == udp_ip_in.end()) {
			double numIP = parseIP(ip);
			for (unsigned int i = 0; i < udp_in_range.size(); i++) {
				if (numIP >= udp_in_range[i].first && numIP <= udp_in_range[i].second) {
					return true;
				}
			}
			return false;
		}
	}
	else if (udp && out) {
		auto itr = udp_ip_out.find(ip);
		if (itr == udp_ip_out.end()) {
			double numIP = parseIP(ip);
			cout << fixed << numIP << endl;
			for (unsigned int i = 0; i < udp_out_range.size(); i++) {
				if (numIP >= udp_out_range[i].first && numIP <= udp_out_range[i].second) {
					return true;
				}
			}
			return false;
		}
	}

	return true;
}

int main() {
	// Initialize Firewall object
	Firewall fw("rules.csv");

	// Testing:
	string line;
	ifstream rule_file("test.csv");
	if (rule_file.is_open()) {
		while (getline(rule_file, line)) {
			// Separate each line into chunks using the delimiter comma
			// (I definitely need to review stringstreams to make this a bit clearer.)
			string prntln = line;
			string direction = line.substr(0, line.find(","));
			line = line.substr(line.find(",")+1);
			string protocol = line.substr(0, line.find(","));
			line = line.substr(line.find(",")+1);
			int port = stoi(line.substr(0, line.find(",")));
			string ip = line.substr(line.find(",")+1);;
		
			string result = fw.accept_packet(direction, protocol, port, ip) ? "true" : "false";
			cout << "> " << prntln << "\n";
			cout << result << "\n";
		}
	}

	// Prevent log from closing.
	cin.get();
	return 0;
}