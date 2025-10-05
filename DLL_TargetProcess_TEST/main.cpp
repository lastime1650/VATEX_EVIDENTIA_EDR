#include "Windows.h"

#include <iostream>

int main()
{

	std::cout << "준비되면 누르시오" << std::endl;
	system("pause");
	std::cout << "IsDebuggerPresent() 의 결과: " << (INT32)( (BOOLEAN)IsDebuggerPresent() ) << std::endl;
	system("pause");

	return 0;
}