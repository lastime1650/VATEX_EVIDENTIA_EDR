#include "Windows.h"

#include <iostream>

int main()
{

	std::cout << "�غ�Ǹ� �����ÿ�" << std::endl;
	system("pause");
	std::cout << "IsDebuggerPresent() �� ���: " << (INT32)( (BOOLEAN)IsDebuggerPresent() ) << std::endl;
	system("pause");

	return 0;
}