#include <iostream>
#include <fstream>
#include <string>
#include <cstring>

bool foo1() {return false;}

bool foo2() {return true;}

void foo3(char* a) {
	std::system("cp example2 example2a && unlink example2");
	std::fstream f;
	f.open("example2a", std::ios::in | std::ios::out);
	f.seekp(0x13A1);
	f.put(0x0);
	std::system("mv example2a example2");
	std::string b = "";
	std::string c = "J9?3?U@A";
	for (int i = 0; i < 8; i++) {
		int temp = c[i] ^ int(a[i]);
		b += char(temp);
	}
	if (memcmp(b.c_str(), ",U^TDcp5", 8) == 0)
		printf("50%% - %s\n", a);
}

void foo4(char* a) {
	std::string b = "";
	std::string c = "V3 >X9l[";
	for (int i = 0; i < 8; i++) {
		int temp = c[i] ^ int(a[i]);
		b += char(temp);
	}
	if (memcmp(b.c_str(), ">lp~,QY&", 8) == 0)
		printf("75%% - %s\n", a);
	std::system("cp example2 example2a && unlink example2");
	std::fstream f;
	f.open("example2a", std::ios::in | std::ios::out);
	f.seekp(0x13A1);
	f.put(0x1);
	std::system("mv example2a example2");
}

int main(int argc, char** argv) {
	if (foo1()) {
		printf("25%% - %i\n", foo1());
		if (foo2()) {
			foo3(argv[1]);
		}
		else {
			foo4(argv[1]);
		}
	}
}
