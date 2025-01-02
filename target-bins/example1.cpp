#include <iostream>
#include <fstream>
#include <string>

void foo(std::string a, int b, int l) {
	std::ifstream i(a, std::ios::binary);
	i.seekg(0x2500);
	std::system("cp example1 example1a && unlink example1");
	std::fstream f;
	f.open("example1a", std::ios::in | std::ios::out);
	f.seekp(b);
	std::system("mv example1a example1");
	char c;
	for (int j = 0; j < l; j++) {
		i >> std::noskipws >> c;
		int temp = (c ^ int(f.peek()));
		f.put((char)temp);
	}
	f.close();
}

void foo1() {
    std::cout << "25%% - flag\n";
}

void foo2() {
    std::cout << "50%% - 8L00\n";
}

void foo3() {
    std::cout << "75%% - dh0u\n";
}

void foo4() {
    std::cout << "100%% add all previous plus - uND}\n";
}

int main(int argc, char** argv) {
	if (argc == 4) {
		foo(std::string(argv[1]), std::atoi(argv[2]), std::atoi(argv[3]));
	}
	else {
		switch (std::atoi(argv[1])) {
			case 1:
				foo1();
				break;
			case 2:
				foo2();
				break;
			case 3:
				foo3();
				break;
			case 4:
				foo4();
				break;
			default:
				return 0;
		}
	}
}
