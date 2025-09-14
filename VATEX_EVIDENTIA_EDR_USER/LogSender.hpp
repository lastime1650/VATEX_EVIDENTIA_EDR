#ifndef LOGSENDER_H
#define LOGSENDER_H

#include "Util.hpp"

namespace EDR
{
	namespace LogSender
	{
		class LogSender
		{
			public:
				LogSender(EDR::Util::Kafka::Kafka& Kafka) : Kafka(Kafka) {}
				~LogSender() = default;

				// ���μ��� ����

			private:
				EDR::Util::Kafka::Kafka& Kafka
		};
	}
}


#endif