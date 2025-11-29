#ifndef DOTNET_ETW_MANAGER_HPP
#define DOTNET_ETW_MANAGER_HPP

#include "Util.hpp"
#include "EventLog.hpp"

#include "LogReceiverShareStruct.hpp" // struct log_s

#include <string>
#include <krabs.hpp>

namespace EDR
{
	namespace ETW
	{
		namespace DOTNET
		{

			namespace Providers
			{
				#define DOTNET_RUNTIME_PROVIDER_GUID L"{e13c0d23-ccbc-4e12-931b-d9cc2eee27e4}"
				const krabs::guid dotnet_runtime_t_provider_guid(DOTNET_RUNTIME_PROVIDER_GUID);
			}


			inline std::string wchar_to_char(const wchar_t* wstr) {
				int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
				std::string strTo(size_needed - 1, 0);
				WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &strTo[0], size_needed, nullptr, nullptr);
				return strTo;
			}

			template<typename T>
			T safe_parse(krabs::parser& parser, const std::wstring& property_name, T default_value = T{}) {
				try {
					return parser.parse<T>(property_name);
				}
				catch (const std::runtime_error&) {
					// 속성이 없으면 예외가 발생하므로, 기본값을 반환합니다.
					return default_value;
				}
			}

			// GC Reason 코드를 문자열로 변환하는 함수
			inline std::wstring get_gc_reason_string(uint32_t reason) {
				switch (reason) {
				case 0: return L"Small object heap allocation";
				case 1: return L"Induced";
				case 2: return L"Low memory";
				case 3: return L"Empty";
				case 4: return L"Large object heap allocation";
				case 5: return L"Out of space (small object heap)";
				case 6: return L"Out of space (large object heap)";
				case 7: return L"Induced but not forced";
				default: return L"Unknown";
				}
			}

			class DotNetManager
			{
			public:
				DotNetManager(EDR::Util::Queue::IQueue& Queue)
					: Queue(Queue),
					dotnet_provider(EDR::ETW::DOTNET::Providers::dotnet_runtime_t_provider_guid)
				{
					this->dotnet_provider.any(0xFFFFFFFFFFFFFFFF); // all subscriptions
					this->dotnet_provider.add_on_event_callback(
						[this](const EVENT_RECORD& record, const krabs::trace_context& context) {
							unsigned long long timestamp = 0;
							EDR::Util::timestamp::Get_Real_Timestamp(&timestamp);

							krabs::schema schema(record, context.schema_locator);
							krabs::parser parser(schema);

							auto* ELS = new EDR::EventLog::Struct::ETW::ETW_Log_Struct();
							RtlZeroMemory(ELS, sizeof(EDR::EventLog::Struct::ETW::ETW_Log_Struct));

							ELS->header.Type = EDR::EventLog::Enum::etw;
							ELS->header.ProcessId = (HANDLE)((ULONG64)schema.process_id());
							ELS->header.NanoTimestamp = timestamp;

							// EventName은 아래 switch-case 문에서 각 이벤트 ID와 버전에 맞게 하드코딩됩니다.
							// std::wstring eventNameW = schema.event_name();
							// if (!eventNameW.empty())
							// {
							// 	std::string eventNameA = wchar_to_char(eventNameW.c_str());
							// 	RtlCopyMemory(ELS->EventName, eventNameA.c_str(), eventNameA.length());
							// }

							ELS->EventId = schema.event_id();
							ELS->EventFlags = schema.event_flags();
							ELS->EventVersion = schema.event_version();

							std::string providerName = "Microsoft-Windows-DotNetRuntime";
							RtlCopyMemory(ELS->ProviderName, providerName.c_str(), providerName.length());

							int field_idx = 0;

							switch (schema.event_id())
							{
							case 1:
							{
								if (schema.event_version() == 0)
								{
									RtlCopyMemory(ELS->EventName, "GCStart", sizeof("GCStart"));

									auto Count = safe_parse<uint32_t>(parser, L"Count");
									auto Reason = safe_parse<uint32_t>(parser, L"Reason");
									ELS->field.FieldCount = 2;
									std::string Count_str = std::to_string(Count);
									std::string Reason_str = std::to_string(Reason);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "count", sizeof("count"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, Count_str.c_str(), Count_str.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "reason", sizeof("reason"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, Reason_str.c_str(), Reason_str.length());
								}
								else if (schema.event_version() == 1)
								{
									RtlCopyMemory(ELS->EventName, "GCStart_V1", sizeof("GCStart_V1"));

									auto Count = safe_parse<uint32_t>(parser, L"Count");
									auto Depth = safe_parse<uint32_t>(parser, L"Depth");
									auto Reason = safe_parse<uint32_t>(parser, L"Reason");
									auto Type = safe_parse<uint32_t>(parser, L"Type");
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS->field.FieldCount = 5;
									std::string Count_str = std::to_string(Count);
									std::string Depth_str = std::to_string(Depth);
									std::string Reason_str = std::to_string(Reason);
									std::string Type_str = std::to_string(Type);
									std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "count", sizeof("count"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, Count_str.c_str(), Count_str.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "depth", sizeof("depth"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, Depth_str.c_str(), Depth_str.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "reason", sizeof("reason"));
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, Reason_str.c_str(), Reason_str.length());
									RtlCopyMemory(ELS->field.Fields[3].FieldName, "type", sizeof("type"));
									RtlCopyMemory(ELS->field.Fields[3].FieldValue, Type_str.c_str(), Type_str.length());
									RtlCopyMemory(ELS->field.Fields[4].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									RtlCopyMemory(ELS->field.Fields[4].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								}
								else if (schema.event_version() == 2)
								{
									RtlCopyMemory(ELS->EventName, "GCStart_V2", sizeof("GCStart_V2"));

									auto Count = safe_parse<uint32_t>(parser, L"Count");
									auto Depth = safe_parse<uint32_t>(parser, L"Depth");
									auto Reason = safe_parse<uint32_t>(parser, L"Reason");
									auto Type = safe_parse<uint32_t>(parser, L"Type");
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									auto ClientSequenceNumber = safe_parse<uint64_t>(parser, L"ClientSequenceNumber");
									ELS->field.FieldCount = 6;
									std::string Count_str = std::to_string(Count);
									std::string Depth_str = std::to_string(Depth);
									std::string Reason_str = std::to_string(Reason);
									std::string Type_str = std::to_string(Type);
									std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
									std::string ClientSequenceNumber_str = std::to_string(ClientSequenceNumber);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "count", sizeof("count"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, Count_str.c_str(), Count_str.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "depth", sizeof("depth"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, Depth_str.c_str(), Depth_str.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "reason", sizeof("reason"));
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, Reason_str.c_str(), Reason_str.length());
									RtlCopyMemory(ELS->field.Fields[3].FieldName, "type", sizeof("type"));
									RtlCopyMemory(ELS->field.Fields[3].FieldValue, Type_str.c_str(), Type_str.length());
									RtlCopyMemory(ELS->field.Fields[4].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									RtlCopyMemory(ELS->field.Fields[4].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
									RtlCopyMemory(ELS->field.Fields[5].FieldName, "clientsequencenumber", sizeof("clientsequencenumber"));
									RtlCopyMemory(ELS->field.Fields[5].FieldValue, ClientSequenceNumber_str.c_str(), ClientSequenceNumber_str.length());
								}
								break;
							}
							case 2:
							{
								if (schema.event_version() == 0)
								{
									RtlCopyMemory(ELS->EventName, "GCStop", sizeof("GCStop"));
									auto Count = safe_parse<uint32_t>(parser, L"Count");
									auto Depth = safe_parse<uint16_t>(parser, L"Depth");
									ELS->field.FieldCount = 2;
									std::string Count_str = std::to_string(Count);
									std::string Depth_str = std::to_string(Depth);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "count", sizeof("count"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, Count_str.c_str(), Count_str.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "depth", sizeof("depth"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, Depth_str.c_str(), Depth_str.length());
								}
								else if (schema.event_version() == 1)
								{
									RtlCopyMemory(ELS->EventName, "GCStop_V1", sizeof("GCStop_V1"));
									auto Count = safe_parse<uint32_t>(parser, L"Count");
									auto Depth = safe_parse<uint32_t>(parser, L"Depth");
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS->field.FieldCount = 3;
									std::string Count_str = std::to_string(Count);
									std::string Depth_str = std::to_string(Depth);
									std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "count", sizeof("count"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, Count_str.c_str(), Count_str.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "depth", sizeof("depth"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, Depth_str.c_str(), Depth_str.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								}
								break;
							}
							case 3:
							{
								if (schema.event_version() == 0)
								{
									RtlCopyMemory(ELS->EventName, "GCRestartEEStop", sizeof("GCRestartEEStop"));
									ELS->field.FieldCount = 0;
								}
								else if (schema.event_version() == 1)
								{
									RtlCopyMemory(ELS->EventName, "GCRestartEEStop_V1", sizeof("GCRestartEEStop_V1"));
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS->field.FieldCount = 1;
									std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								}
								break;
							}
							case 4:
							{
								if (schema.event_version() == 0)
								{
									RtlCopyMemory(ELS->EventName, "GCHeapStats", sizeof("GCHeapStats"));
									auto GenerationSize0 = safe_parse<uint64_t>(parser, L"GenerationSize0");
									auto TotalPromotedSize0 = safe_parse<uint64_t>(parser, L"TotalPromotedSize0");
									auto GenerationSize1 = safe_parse<uint64_t>(parser, L"GenerationSize1");
									auto TotalPromotedSize1 = safe_parse<uint64_t>(parser, L"TotalPromotedSize1");
									auto GenerationSize2 = safe_parse<uint64_t>(parser, L"GenerationSize2");
									auto TotalPromotedSize2 = safe_parse<uint64_t>(parser, L"TotalPromotedSize2");
									auto GenerationSize3 = safe_parse<uint64_t>(parser, L"GenerationSize3");
									auto TotalPromotedSize3 = safe_parse<uint64_t>(parser, L"TotalPromotedSize3");
									auto FinalizationPromotedSize = safe_parse<uint64_t>(parser, L"FinalizationPromotedSize");
									auto FinalizationPromotedCount = safe_parse<uint64_t>(parser, L"FinalizationPromotedCount");
									auto PinnedObjectCount = safe_parse<uint32_t>(parser, L"PinnedObjectCount");
									auto SinkBlockCount = safe_parse<uint32_t>(parser, L"SinkBlockCount");
									auto GCHandleCount = safe_parse<uint32_t>(parser, L"GCHandleCount");
									ELS->field.FieldCount = 13;

									field_idx = 0;
									RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "generationsize0", sizeof("generationsize0"));
									std::string GenSize0_str = std::to_string(GenerationSize0);
									RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, GenSize0_str.c_str(), GenSize0_str.length());
									RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "totalpromotedsize0", sizeof("totalpromotedsize0"));
									std::string Promoted0_str = std::to_string(TotalPromotedSize0);
									RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, Promoted0_str.c_str(), Promoted0_str.length());
									RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "generationsize1", sizeof("generationsize1"));
									std::string GenSize1_str = std::to_string(GenerationSize1);
									RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, GenSize1_str.c_str(), GenSize1_str.length());
									RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "totalpromotedsize1", sizeof("totalpromotedsize1"));
									std::string Promoted1_str = std::to_string(TotalPromotedSize1);
									RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, Promoted1_str.c_str(), Promoted1_str.length());
									RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "generationsize2", sizeof("generationsize2"));
									std::string GenSize2_str = std::to_string(GenerationSize2);
									RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, GenSize2_str.c_str(), GenSize2_str.length());
									RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "totalpromotedsize2", sizeof("totalpromotedsize2"));
									std::string Promoted2_str = std::to_string(TotalPromotedSize2);
									RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, Promoted2_str.c_str(), Promoted2_str.length());
									RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "generationsize3", sizeof("generationsize3"));
									std::string GenSize3_str = std::to_string(GenerationSize3);
									RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, GenSize3_str.c_str(), GenSize3_str.length());
									RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "totalpromotedsize3", sizeof("totalpromotedsize3"));
									std::string Promoted3_str = std::to_string(TotalPromotedSize3);
									RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, Promoted3_str.c_str(), Promoted3_str.length());
									RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "finalizationpromotedsize", sizeof("finalizationpromotedsize"));
									std::string FinalPromotedSize_str = std::to_string(FinalizationPromotedSize);
									RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, FinalPromotedSize_str.c_str(), FinalPromotedSize_str.length());
									RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "finalizationpromotedcount", sizeof("finalizationpromotedcount"));
									std::string FinalPromotedCount_str = std::to_string(FinalizationPromotedCount);
									RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, FinalPromotedCount_str.c_str(), FinalPromotedCount_str.length());
									RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "pinnedobjectcount", sizeof("pinnedobjectcount"));
									std::string PinnedCount_str = std::to_string(PinnedObjectCount);
									RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, PinnedCount_str.c_str(), PinnedCount_str.length());
									RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "sinkblockcount", sizeof("sinkblockcount"));
									std::string SinkCount_str = std::to_string(SinkBlockCount);
									RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, SinkCount_str.c_str(), SinkCount_str.length());
									RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "gchandlecount", sizeof("gchandlecount"));
									std::string HandleCount_str = std::to_string(GCHandleCount);
									RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, HandleCount_str.c_str(), HandleCount_str.length());
								}
								else if (schema.event_version() == 1)
								{
									RtlCopyMemory(ELS->EventName, "GCHeapStats_V1", sizeof("GCHeapStats_V1"));
									auto GenerationSize0 = safe_parse<uint64_t>(parser, L"GenerationSize0");
									auto TotalPromotedSize0 = safe_parse<uint64_t>(parser, L"TotalPromotedSize0");
									auto GenerationSize1 = safe_parse<uint64_t>(parser, L"GenerationSize1");
									auto TotalPromotedSize1 = safe_parse<uint64_t>(parser, L"TotalPromotedSize1");
									auto GenerationSize2 = safe_parse<uint64_t>(parser, L"GenerationSize2");
									auto TotalPromotedSize2 = safe_parse<uint64_t>(parser, L"TotalPromotedSize2");
									auto GenerationSize3 = safe_parse<uint64_t>(parser, L"GenerationSize3");
									auto TotalPromotedSize3 = safe_parse<uint64_t>(parser, L"TotalPromotedSize3");
									auto FinalizationPromotedSize = safe_parse<uint64_t>(parser, L"FinalizationPromotedSize");
									auto FinalizationPromotedCount = safe_parse<uint64_t>(parser, L"FinalizationPromotedCount");
									auto PinnedObjectCount = safe_parse<uint32_t>(parser, L"PinnedObjectCount");
									auto SinkBlockCount = safe_parse<uint32_t>(parser, L"SinkBlockCount");
									auto GCHandleCount = safe_parse<uint32_t>(parser, L"GCHandleCount");
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS->field.FieldCount = 14;

									field_idx = 0;
									RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "generationsize0", sizeof("generationsize0"));
									std::string GenSize0_str = std::to_string(GenerationSize0);
									RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, GenSize0_str.c_str(), GenSize0_str.length());
									RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "totalpromotedsize0", sizeof("totalpromotedsize0"));
									std::string Promoted0_str = std::to_string(TotalPromotedSize0);
									RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, Promoted0_str.c_str(), Promoted0_str.length());
									RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "generationsize1", sizeof("generationsize1"));
									std::string GenSize1_str = std::to_string(GenerationSize1);
									RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, GenSize1_str.c_str(), GenSize1_str.length());
									RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "totalpromotedsize1", sizeof("totalpromotedsize1"));
									std::string Promoted1_str = std::to_string(TotalPromotedSize1);
									RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, Promoted1_str.c_str(), Promoted1_str.length());
									RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "generationsize2", sizeof("generationsize2"));
									std::string GenSize2_str = std::to_string(GenerationSize2);
									RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, GenSize2_str.c_str(), GenSize2_str.length());
									RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "totalpromotedsize2", sizeof("totalpromotedsize2"));
									std::string Promoted2_str = std::to_string(TotalPromotedSize2);
									RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, Promoted2_str.c_str(), Promoted2_str.length());
									RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "generationsize3", sizeof("generationsize3"));
									std::string GenSize3_str = std::to_string(GenerationSize3);
									RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, GenSize3_str.c_str(), GenSize3_str.length());
									RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "totalpromotedsize3", sizeof("totalpromotedsize3"));
									std::string Promoted3_str = std::to_string(TotalPromotedSize3);
									RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, Promoted3_str.c_str(), Promoted3_str.length());
									RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "finalizationpromotedsize", sizeof("finalizationpromotedsize"));
									std::string FinalPromotedSize_str = std::to_string(FinalizationPromotedSize);
									RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, FinalPromotedSize_str.c_str(), FinalPromotedSize_str.length());
									RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "finalizationpromotedcount", sizeof("finalizationpromotedcount"));
									std::string FinalPromotedCount_str = std::to_string(FinalizationPromotedCount);
									RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, FinalPromotedCount_str.c_str(), FinalPromotedCount_str.length());
									RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "pinnedobjectcount", sizeof("pinnedobjectcount"));
									std::string PinnedCount_str = std::to_string(PinnedObjectCount);
									RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, PinnedCount_str.c_str(), PinnedCount_str.length());
									RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "sinkblockcount", sizeof("sinkblockcount"));
									std::string SinkCount_str = std::to_string(SinkBlockCount);
									RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, SinkCount_str.c_str(), SinkCount_str.length());
									RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "gchandlecount", sizeof("gchandlecount"));
									std::string HandleCount_str = std::to_string(GCHandleCount);
									RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, HandleCount_str.c_str(), HandleCount_str.length());
									std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								}
								break;
							}
							case 5:
							{
								if (schema.event_version() == 0)
								{
									RtlCopyMemory(ELS->EventName, "GCCreateSegment", sizeof("GCCreateSegment"));
									auto Address = safe_parse<uint64_t>(parser, L"Address");
									auto Size = safe_parse<uint64_t>(parser, L"Size");
									auto Type = safe_parse<uint32_t>(parser, L"Type");
									ELS->field.FieldCount = 3;
									std::string Address_str = std::to_string(Address);
									std::string Size_str = std::to_string(Size);
									std::string Type_str = std::to_string(Type);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "address", sizeof("address"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, Address_str.c_str(), Address_str.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "size", sizeof("size"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, Size_str.c_str(), Size_str.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "type", sizeof("type"));
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, Type_str.c_str(), Type_str.length());
								}
								else if (schema.event_version() == 1)
								{
									RtlCopyMemory(ELS->EventName, "GCCreateSegment_V1", sizeof("GCCreateSegment_V1"));
									auto Address = safe_parse<uint64_t>(parser, L"Address");
									auto Size = safe_parse<uint64_t>(parser, L"Size");
									auto Type = safe_parse<uint32_t>(parser, L"Type");
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS->field.FieldCount = 4;
									std::string Address_str = std::to_string(Address);
									std::string Size_str = std::to_string(Size);
									std::string Type_str = std::to_string(Type);
									std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "address", sizeof("address"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, Address_str.c_str(), Address_str.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "size", sizeof("size"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, Size_str.c_str(), Size_str.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "type", sizeof("type"));
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, Type_str.c_str(), Type_str.length());
									RtlCopyMemory(ELS->field.Fields[3].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									RtlCopyMemory(ELS->field.Fields[3].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								}
								break;
							}
							case 6:
							{
								if (schema.event_version() == 0)
								{
									RtlCopyMemory(ELS->EventName, "GCFreeSegment", sizeof("GCFreeSegment"));
									auto Address = safe_parse<uint64_t>(parser, L"Address");
									ELS->field.FieldCount = 1;
									std::string Address_str = std::to_string(Address);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "address", sizeof("address"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, Address_str.c_str(), Address_str.length());
								}
								else if (schema.event_version() == 1)
								{
									RtlCopyMemory(ELS->EventName, "GCFreeSegment_V1", sizeof("GCFreeSegment_V1"));
									auto Address = safe_parse<uint64_t>(parser, L"Address");
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS->field.FieldCount = 2;
									std::string Address_str = std::to_string(Address);
									std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "address", sizeof("address"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, Address_str.c_str(), Address_str.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								}
								break;
							}
							case 7:
							{
								if (schema.event_version() == 0)
								{
									RtlCopyMemory(ELS->EventName, "GCRestartEEStart", sizeof("GCRestartEEStart"));
									ELS->field.FieldCount = 0;
								}
								else if (schema.event_version() == 1)
								{
									RtlCopyMemory(ELS->EventName, "GCRestartEEStart_V1", sizeof("GCRestartEEStart_V1"));
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS->field.FieldCount = 1;
									std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								}
								break;
							}
							case 8:
							{
								if (schema.event_version() == 0)
								{
									RtlCopyMemory(ELS->EventName, "GCSuspendEEStop", sizeof("GCSuspendEEStop"));
									ELS->field.FieldCount = 0;
								}
								else if (schema.event_version() == 1)
								{
									RtlCopyMemory(ELS->EventName, "GCSuspendEEStop_V1", sizeof("GCSuspendEEStop_V1"));
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS->field.FieldCount = 1;
									std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								}
								break;
							}
							case 9:
							{
								if (schema.event_version() == 0)
								{
									RtlCopyMemory(ELS->EventName, "GCSuspendEEStart", sizeof("GCSuspendEEStart"));
									auto Reason = safe_parse<uint16_t>(parser, L"Reason");
									ELS->field.FieldCount = 1;
									std::string Reason_str = std::to_string(Reason);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "reason", sizeof("reason"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, Reason_str.c_str(), Reason_str.length());
								}
								else if (schema.event_version() == 1)
								{
									RtlCopyMemory(ELS->EventName, "GCSuspendEEStart_V1", sizeof("GCSuspendEEStart_V1"));
									auto Reason = safe_parse<uint32_t>(parser, L"Reason");
									auto Count = safe_parse<uint32_t>(parser, L"Count");
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS->field.FieldCount = 3;
									std::string Reason_str = std::to_string(Reason);
									std::string Count_str = std::to_string(Count);
									std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "reason", sizeof("reason"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, Reason_str.c_str(), Reason_str.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "count", sizeof("count"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, Count_str.c_str(), Count_str.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								}
								break;
							}
							case 10:
							{
								if (schema.event_version() == 0)
								{
									RtlCopyMemory(ELS->EventName, "GCAllocationTick", sizeof("GCAllocationTick"));
									auto AllocationAmount = safe_parse<uint32_t>(parser, L"AllocationAmount");
									auto AllocationKind = safe_parse<uint32_t>(parser, L"AllocationKind");
									ELS->field.FieldCount = 2;
									std::string AllocationAmount_str = std::to_string(AllocationAmount);
									std::string AllocationKind_str = std::to_string(AllocationKind);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "allocationamount", sizeof("allocationamount"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, AllocationAmount_str.c_str(), AllocationAmount_str.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "allocationkind", sizeof("allocationkind"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, AllocationKind_str.c_str(), AllocationKind_str.length());
								}
								else if (schema.event_version() == 1)
								{
									RtlCopyMemory(ELS->EventName, "GCAllocationTick_V1", sizeof("GCAllocationTick_V1"));
									auto AllocationAmount = safe_parse<uint32_t>(parser, L"AllocationAmount");
									auto AllocationKind = safe_parse<uint32_t>(parser, L"AllocationKind");
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS->field.FieldCount = 3;
									std::string AllocationAmount_str = std::to_string(AllocationAmount);
									std::string AllocationKind_str = std::to_string(AllocationKind);
									std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "allocationamount", sizeof("allocationamount"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, AllocationAmount_str.c_str(), AllocationAmount_str.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "allocationkind", sizeof("allocationkind"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, AllocationKind_str.c_str(), AllocationKind_str.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								}
								else if (schema.event_version() == 2)
								{
									RtlCopyMemory(ELS->EventName, "GCAllocationTick_V2", sizeof("GCAllocationTick_V2"));
									auto AllocationAmount = safe_parse<uint32_t>(parser, L"AllocationAmount");
									auto AllocationKind = safe_parse<uint32_t>(parser, L"AllocationKind");
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									auto AllocationAmount64 = safe_parse<uint64_t>(parser, L"AllocationAmount64");
									auto TypeID = safe_parse<uint64_t>(parser, L"TypeID"); // Pointer
									auto TypeName = wchar_to_char((safe_parse<std::wstring>(parser, L"TypeName")).c_str());
									auto HeapIndex = safe_parse<uint32_t>(parser, L"HeapIndex");
									ELS->field.FieldCount = 7;
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "allocationamount", sizeof("allocationamount"));
									std::string s0 = std::to_string(AllocationAmount);
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "allocationkind", sizeof("allocationkind"));
									std::string s1 = std::to_string(AllocationKind);
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									std::string s2 = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
									RtlCopyMemory(ELS->field.Fields[3].FieldName, "allocationamount64", sizeof("allocationamount64"));
									std::string s3 = std::to_string(AllocationAmount64);
									RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
									RtlCopyMemory(ELS->field.Fields[4].FieldName, "typeid", sizeof("typeid"));
									std::string s4 = std::to_string(TypeID);
									RtlCopyMemory(ELS->field.Fields[4].FieldValue, s4.c_str(), s4.length());
									RtlCopyMemory(ELS->field.Fields[5].FieldName, "typename", sizeof("typename"));
									RtlCopyMemory(ELS->field.Fields[5].FieldValue, TypeName.c_str(), TypeName.length());
									RtlCopyMemory(ELS->field.Fields[6].FieldName, "heapindex", sizeof("heapindex"));
									std::string s6 = std::to_string(HeapIndex);
									RtlCopyMemory(ELS->field.Fields[6].FieldValue, s6.c_str(), s6.length());
								}
								else if (schema.event_version() == 3)
								{
									RtlCopyMemory(ELS->EventName, "GCAllocationTick_V3", sizeof("GCAllocationTick_V3"));
									auto AllocationAmount = safe_parse<uint32_t>(parser, L"AllocationAmount");
									auto AllocationKind = safe_parse<uint32_t>(parser, L"AllocationKind");
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									auto AllocationAmount64 = safe_parse<uint64_t>(parser, L"AllocationAmount64");
									auto TypeID = safe_parse<uint64_t>(parser, L"TypeID");
									auto TypeName = wchar_to_char((safe_parse<std::wstring>(parser, L"TypeName")).c_str());
									auto HeapIndex = safe_parse<uint32_t>(parser, L"HeapIndex");
									auto Address = safe_parse<uint64_t>(parser, L"Address");
									ELS->field.FieldCount = 8;
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "allocationamount", sizeof("allocationamount"));
									std::string s0 = std::to_string(AllocationAmount);
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "allocationkind", sizeof("allocationkind"));
									std::string s1 = std::to_string(AllocationKind);
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									std::string s2 = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
									RtlCopyMemory(ELS->field.Fields[3].FieldName, "allocationamount64", sizeof("allocationamount64"));
									std::string s3 = std::to_string(AllocationAmount64);
									RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
									RtlCopyMemory(ELS->field.Fields[4].FieldName, "typeid", sizeof("typeid"));
									std::string s4 = std::to_string(TypeID);
									RtlCopyMemory(ELS->field.Fields[4].FieldValue, s4.c_str(), s4.length());
									RtlCopyMemory(ELS->field.Fields[5].FieldName, "typename", sizeof("typename"));
									RtlCopyMemory(ELS->field.Fields[5].FieldValue, TypeName.c_str(), TypeName.length());
									RtlCopyMemory(ELS->field.Fields[6].FieldName, "heapindex", sizeof("heapindex"));
									std::string s6 = std::to_string(HeapIndex);
									RtlCopyMemory(ELS->field.Fields[6].FieldValue, s6.c_str(), s6.length());
									RtlCopyMemory(ELS->field.Fields[7].FieldName, "address", sizeof("address"));
									std::string s7 = std::to_string(Address);
									RtlCopyMemory(ELS->field.Fields[7].FieldValue, s7.c_str(), s7.length());
								}
								break;
							}
							case 11:
							{
								if (schema.event_version() == 0)
								{
									RtlCopyMemory(ELS->EventName, "GCCreateConcurrentThread", sizeof("GCCreateConcurrentThread"));
									ELS->field.FieldCount = 0;
								}
								else if (schema.event_version() == 1)
								{
									RtlCopyMemory(ELS->EventName, "GCCreateConcurrentThread_V1", sizeof("GCCreateConcurrentThread_V1"));
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS->field.FieldCount = 1;
									std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								}
								break;
							}
							case 12:
							{
								if (schema.event_version() == 0)
								{
									RtlCopyMemory(ELS->EventName, "GCTerminateConcurrentThread", sizeof("GCTerminateConcurrentThread"));
									ELS->field.FieldCount = 0;
								}
								else if (schema.event_version() == 1)
								{
									RtlCopyMemory(ELS->EventName, "GCTerminateConcurrentThread_V1", sizeof("GCTerminateConcurrentThread_V1"));
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS->field.FieldCount = 1;
									std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								}
								break;
							}
							case 13:
							{
								if (schema.event_version() == 0)
								{
									RtlCopyMemory(ELS->EventName, "GCFinalizersStop", sizeof("GCFinalizersStop"));
									auto Count = safe_parse<uint32_t>(parser, L"Count");
									ELS->field.FieldCount = 1;
									std::string Count_str = std::to_string(Count);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "count", sizeof("count"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, Count_str.c_str(), Count_str.length());
								}
								else if (schema.event_version() == 1)
								{
									RtlCopyMemory(ELS->EventName, "GCFinalizersStop_V1", sizeof("GCFinalizersStop_V1"));
									auto Count = safe_parse<uint32_t>(parser, L"Count");
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS->field.FieldCount = 2;
									std::string Count_str = std::to_string(Count);
									std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "count", sizeof("count"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, Count_str.c_str(), Count_str.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								}
								break;
							}
							case 14:
							{
								if (schema.event_version() == 0)
								{
									RtlCopyMemory(ELS->EventName, "GCFinalizersStart", sizeof("GCFinalizersStart"));
									ELS->field.FieldCount = 0;
								}
								else if (schema.event_version() == 1)
								{
									RtlCopyMemory(ELS->EventName, "GCFinalizersStart_V1", sizeof("GCFinalizersStart_V1"));
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS->field.FieldCount = 1;
									std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								}
								break;
							}
							case 15:
							{
								RtlCopyMemory(ELS->EventName, "TypeBulkType", sizeof("TypeBulkType"));
								auto Count = safe_parse<uint32_t>(parser, L"Count");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 2;
								std::string Count_str = std::to_string(Count);
								std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "count", sizeof("count"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, Count_str.c_str(), Count_str.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								break;
							}
							case 16:
							{
								RtlCopyMemory(ELS->EventName, "GCGCBulkRootEdge", sizeof("GCGCBulkRootEdge"));
								auto Index = safe_parse<uint32_t>(parser, L"Index");
								auto Count = safe_parse<uint32_t>(parser, L"Count");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 3;
								std::string Index_str = std::to_string(Index);
								std::string Count_str = std::to_string(Count);
								std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "index", sizeof("index"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, Index_str.c_str(), Index_str.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "count", sizeof("count"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, Count_str.c_str(), Count_str.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								break;
							}
							case 17:
							{
								RtlCopyMemory(ELS->EventName, "GCGCBulkRootConditionalWeakTableElementEdge", sizeof("GCGCBulkRootConditionalWeakTableElementEdge"));
								auto Index = safe_parse<uint32_t>(parser, L"Index");
								auto Count = safe_parse<uint32_t>(parser, L"Count");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 3;
								std::string Index_str = std::to_string(Index);
								std::string Count_str = std::to_string(Count);
								std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "index", sizeof("index"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, Index_str.c_str(), Index_str.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "count", sizeof("count"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, Count_str.c_str(), Count_str.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								break;
							}
							case 18:
							{
								RtlCopyMemory(ELS->EventName, "GCGCBulkNode", sizeof("GCGCBulkNode"));
								auto Index = safe_parse<uint32_t>(parser, L"Index");
								auto Count = safe_parse<uint32_t>(parser, L"Count");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 3;
								std::string Index_str = std::to_string(Index);
								std::string Count_str = std::to_string(Count);
								std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "index", sizeof("index"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, Index_str.c_str(), Index_str.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "count", sizeof("count"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, Count_str.c_str(), Count_str.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								break;
							}
							case 19:
							{
								RtlCopyMemory(ELS->EventName, "GCGCBulkEdge", sizeof("GCGCBulkEdge"));
								auto Index = safe_parse<uint32_t>(parser, L"Index");
								auto Count = safe_parse<uint32_t>(parser, L"Count");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 3;
								std::string Index_str = std::to_string(Index);
								std::string Count_str = std::to_string(Count);
								std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "index", sizeof("index"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, Index_str.c_str(), Index_str.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "count", sizeof("count"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, Count_str.c_str(), Count_str.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								break;
							}
							case 20:
							{
								RtlCopyMemory(ELS->EventName, "GCGCSampledObjectAllocation", sizeof("GCGCSampledObjectAllocation"));
								auto Address = safe_parse<uint64_t>(parser, L"Address");
								auto TypeID = safe_parse<uint64_t>(parser, L"TypeID");
								auto ObjectCountForTypeSample = safe_parse<uint32_t>(parser, L"ObjectCountForTypeSample");
								auto TotalSizeForTypeSample = safe_parse<uint64_t>(parser, L"TotalSizeForTypeSample");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 5;
								std::string s0 = std::to_string(Address);
								std::string s1 = std::to_string(TypeID);
								std::string s2 = std::to_string(ObjectCountForTypeSample);
								std::string s3 = std::to_string(TotalSizeForTypeSample);
								std::string s4 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "address", sizeof("address"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "typeid", sizeof("typeid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "objectcountfortypesample", sizeof("objectcountfortypesample"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS->field.Fields[3].FieldName, "totalsizefortypesample", sizeof("totalsizefortypesample"));
								RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
								RtlCopyMemory(ELS->field.Fields[4].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[4].FieldValue, s4.c_str(), s4.length());
								break;
							}
							case 21:
							{
								RtlCopyMemory(ELS->EventName, "GCGCBulkSurvivingObjectRanges", sizeof("GCGCBulkSurvivingObjectRanges"));
								auto Index = safe_parse<uint32_t>(parser, L"Index");
								auto Count = safe_parse<uint32_t>(parser, L"Count");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 3;
								std::string Index_str = std::to_string(Index);
								std::string Count_str = std::to_string(Count);
								std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "index", sizeof("index"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, Index_str.c_str(), Index_str.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "count", sizeof("count"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, Count_str.c_str(), Count_str.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								break;
							}
							case 22:
							{
								RtlCopyMemory(ELS->EventName, "GCGCBulkMovedObjectRanges", sizeof("GCGCBulkMovedObjectRanges"));
								auto Index = safe_parse<uint32_t>(parser, L"Index");
								auto Count = safe_parse<uint32_t>(parser, L"Count");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 3;
								std::string Index_str = std::to_string(Index);
								std::string Count_str = std::to_string(Count);
								std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "index", sizeof("index"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, Index_str.c_str(), Index_str.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "count", sizeof("count"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, Count_str.c_str(), Count_str.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								break;
							}
							case 23:
							{
								RtlCopyMemory(ELS->EventName, "GCGCGenerationRange", sizeof("GCGCGenerationRange"));
								auto Generation = safe_parse<uint8_t>(parser, L"Generation");
								auto RangeStart = safe_parse<uint64_t>(parser, L"RangeStart");
								auto RangeUsedLength = safe_parse<uint64_t>(parser, L"RangeUsedLength");
								auto RangeReservedLength = safe_parse<uint64_t>(parser, L"RangeReservedLength");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 5;
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "generation", sizeof("generation"));
								std::string s0 = std::to_string(Generation);
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "rangestart", sizeof("rangestart"));
								std::string s1 = std::to_string(RangeStart);
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "rangeusedlength", sizeof("rangeusedlength"));
								std::string s2 = std::to_string(RangeUsedLength);
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS->field.Fields[3].FieldName, "rangereservedlength", sizeof("rangereservedlength"));
								std::string s3 = std::to_string(RangeReservedLength);
								RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
								RtlCopyMemory(ELS->field.Fields[4].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								std::string s4 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[4].FieldValue, s4.c_str(), s4.length());
								break;
							}
							case 25:
							{
								RtlCopyMemory(ELS->EventName, "GCMarkStackRoots", sizeof("GCMarkStackRoots"));
								auto HeapNum = safe_parse<uint32_t>(parser, L"HeapNum");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 2;
								std::string HeapNum_str = std::to_string(HeapNum);
								std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "heapnum", sizeof("heapnum"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, HeapNum_str.c_str(), HeapNum_str.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								break;
							}
							case 26:
							{
								RtlCopyMemory(ELS->EventName, "GCMarkFinalizeQueueRoots", sizeof("GCMarkFinalizeQueueRoots"));
								auto HeapNum = safe_parse<uint32_t>(parser, L"HeapNum");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 2;
								std::string HeapNum_str = std::to_string(HeapNum);
								std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "heapnum", sizeof("heapnum"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, HeapNum_str.c_str(), HeapNum_str.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								break;
							}
							case 27:
							{
								RtlCopyMemory(ELS->EventName, "GCMarkHandles", sizeof("GCMarkHandles"));
								auto HeapNum = safe_parse<uint32_t>(parser, L"HeapNum");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 2;
								std::string HeapNum_str = std::to_string(HeapNum);
								std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "heapnum", sizeof("heapnum"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, HeapNum_str.c_str(), HeapNum_str.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								break;
							}
							case 28:
							{
								RtlCopyMemory(ELS->EventName, "GCMarkCards", sizeof("GCMarkCards"));
								auto HeapNum = safe_parse<uint32_t>(parser, L"HeapNum");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 2;
								std::string HeapNum_str = std::to_string(HeapNum);
								std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "heapnum", sizeof("heapnum"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, HeapNum_str.c_str(), HeapNum_str.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								break;
							}
							case 29:
							{
								RtlCopyMemory(ELS->EventName, "GCFinalizeObject", sizeof("GCFinalizeObject"));
								auto TypeID = safe_parse<uint64_t>(parser, L"TypeID");
								auto ObjectID = safe_parse<uint64_t>(parser, L"ObjectID");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 3;
								std::string s0 = std::to_string(TypeID);
								std::string s1 = std::to_string(ObjectID);
								std::string s2 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "typeid", sizeof("typeid"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "objectid", sizeof("objectid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								break;
							}
							case 30:
							{
								RtlCopyMemory(ELS->EventName, "GCSetGCHandle", sizeof("GCSetGCHandle"));
								auto HandleID = safe_parse<uint64_t>(parser, L"HandleID");
								auto ObjectID = safe_parse<uint64_t>(parser, L"ObjectID");
								auto Kind = safe_parse<uint32_t>(parser, L"Kind");
								auto Generation = safe_parse<uint32_t>(parser, L"Generation");
								auto AppDomainID = safe_parse<uint64_t>(parser, L"AppDomainID");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 6;
								std::string s0 = std::to_string(HandleID);
								std::string s1 = std::to_string(ObjectID);
								std::string s2 = std::to_string(Kind);
								std::string s3 = std::to_string(Generation);
								std::string s4 = std::to_string(AppDomainID);
								std::string s5 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "handleid", sizeof("handleid"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "objectid", sizeof("objectid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "kind", sizeof("kind"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS->field.Fields[3].FieldName, "generation", sizeof("generation"));
								RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
								RtlCopyMemory(ELS->field.Fields[4].FieldName, "appdomainid", sizeof("appdomainid"));
								RtlCopyMemory(ELS->field.Fields[4].FieldValue, s4.c_str(), s4.length());
								RtlCopyMemory(ELS->field.Fields[5].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[5].FieldValue, s5.c_str(), s5.length());
								break;
							}
							case 31:
							{
								RtlCopyMemory(ELS->EventName, "GCDestoryGCHandle", sizeof("GCDestoryGCHandle"));
								auto HandleID = safe_parse<uint64_t>(parser, L"HandleID");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 2;
								std::string s0 = std::to_string(HandleID);
								std::string s1 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "handleid", sizeof("handleid"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								break;
							}
							case 32:
							{
								RtlCopyMemory(ELS->EventName, "GCGCSampledObjectAllocation32", sizeof("GCGCSampledObjectAllocation32"));
								auto Address = safe_parse<uint64_t>(parser, L"Address");
								auto TypeID = safe_parse<uint64_t>(parser, L"TypeID");
								auto ObjectCountForTypeSample = safe_parse<uint32_t>(parser, L"ObjectCountForTypeSample");
								auto TotalSizeForTypeSample = safe_parse<uint64_t>(parser, L"TotalSizeForTypeSample");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 5;
								std::string s0 = std::to_string(Address);
								std::string s1 = std::to_string(TypeID);
								std::string s2 = std::to_string(ObjectCountForTypeSample);
								std::string s3 = std::to_string(TotalSizeForTypeSample);
								std::string s4 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "address", sizeof("address"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "typeid", sizeof("typeid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "objectcountfortypesample", sizeof("objectcountfortypesample"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS->field.Fields[3].FieldName, "totalsizefortypesample", sizeof("totalsizefortypesample"));
								RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
								RtlCopyMemory(ELS->field.Fields[4].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[4].FieldValue, s4.c_str(), s4.length());
								break;
							}
							case 33:
							{
								RtlCopyMemory(ELS->EventName, "GCPinObjectAtGCTime", sizeof("GCPinObjectAtGCTime"));
								auto HandleID = safe_parse<uint64_t>(parser, L"HandleID");
								auto ObjectID = safe_parse<uint64_t>(parser, L"ObjectID");
								auto ObjectSize = safe_parse<uint64_t>(parser, L"ObjectSize");
								auto TypeName = wchar_to_char((safe_parse<std::wstring>(parser, L"TypeName")).c_str());
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 5;
								std::string s0 = std::to_string(HandleID);
								std::string s1 = std::to_string(ObjectID);
								std::string s2 = std::to_string(ObjectSize);
								std::string s4 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "handleid", sizeof("handleid"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "objectid", sizeof("objectid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "objectsize", sizeof("objectsize"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS->field.Fields[3].FieldName, "typename", sizeof("typename"));
								RtlCopyMemory(ELS->field.Fields[3].FieldValue, TypeName.c_str(), TypeName.length());
								RtlCopyMemory(ELS->field.Fields[4].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[4].FieldValue, s4.c_str(), s4.length());
								break;
							}
							case 35:
							{
								RtlCopyMemory(ELS->EventName, "GCTriggered", sizeof("GCTriggered"));
								auto Reason = safe_parse<uint32_t>(parser, L"Reason");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 2;
								std::string s0 = std::to_string(Reason);
								std::string s1 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "reason", sizeof("reason"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								break;
							}
							case 36:
							{
								RtlCopyMemory(ELS->EventName, "GCGCBulkRootCCW", sizeof("GCGCBulkRootCCW"));
								auto Count = safe_parse<uint32_t>(parser, L"Count");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 2;
								std::string Count_str = std::to_string(Count);
								std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "count", sizeof("count"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, Count_str.c_str(), Count_str.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								break;
							}
							case 37:
							{
								RtlCopyMemory(ELS->EventName, "GCGCBulkRCW", sizeof("GCGCBulkRCW"));
								auto Count = safe_parse<uint32_t>(parser, L"Count");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 2;
								std::string Count_str = std::to_string(Count);
								std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "count", sizeof("count"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, Count_str.c_str(), Count_str.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								break;
							}
							case 38:
							{
								RtlCopyMemory(ELS->EventName, "GCGCBulkRootStaticVar", sizeof("GCGCBulkRootStaticVar"));
								auto Count = safe_parse<uint32_t>(parser, L"Count");
								auto AppDomainID = safe_parse<uint64_t>(parser, L"AppDomainID");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 3;
								std::string s0 = std::to_string(Count);
								std::string s1 = std::to_string(AppDomainID);
								std::string s2 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "count", sizeof("count"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "appdomainid", sizeof("appdomainid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								break;
							}
							case 39:
							{
								RtlCopyMemory(ELS->EventName, "GCGCDynamicEvent", sizeof("GCGCDynamicEvent"));
								auto Name = wchar_to_char((safe_parse<std::wstring>(parser, L"Name")).c_str());
								auto DataSize = safe_parse<uint32_t>(parser, L"DataSize");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 3;
								std::string s1 = std::to_string(DataSize);
								std::string s2 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "name", sizeof("name"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, Name.c_str(), Name.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "datasize", sizeof("datasize"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								break;
							}
							case 40:
							{
								RtlCopyMemory(ELS->EventName, "WorkerThreadCreationV2Start", sizeof("WorkerThreadCreationV2Start"));
								auto WorkerThreadCount = safe_parse<uint32_t>(parser, L"WorkerThreadCount");
								auto RetiredWorkerThreads = safe_parse<uint32_t>(parser, L"RetiredWorkerThreads");
								ELS->field.FieldCount = 2;
								std::string s0 = std::to_string(WorkerThreadCount);
								std::string s1 = std::to_string(RetiredWorkerThreads);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "workerthreadcount", sizeof("workerthreadcount"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "retiredworkerthreads", sizeof("retiredworkerthreads"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								break;
							}
							case 41:
							{
								RtlCopyMemory(ELS->EventName, "WorkerThreadCreationV2Stop", sizeof("WorkerThreadCreationV2Stop"));
								auto WorkerThreadCount = safe_parse<uint32_t>(parser, L"WorkerThreadCount");
								auto RetiredWorkerThreads = safe_parse<uint32_t>(parser, L"RetiredWorkerThreads");
								ELS->field.FieldCount = 2;
								std::string s0 = std::to_string(WorkerThreadCount);
								std::string s1 = std::to_string(RetiredWorkerThreads);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "workerthreadcount", sizeof("workerthreadcount"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "retiredworkerthreads", sizeof("retiredworkerthreads"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								break;
							}
							case 42:
							{
								RtlCopyMemory(ELS->EventName, "WorkerThreadRetirementV2Start", sizeof("WorkerThreadRetirementV2Start"));
								auto WorkerThreadCount = safe_parse<uint32_t>(parser, L"WorkerThreadCount");
								auto RetiredWorkerThreads = safe_parse<uint32_t>(parser, L"RetiredWorkerThreads");
								ELS->field.FieldCount = 2;
								std::string s0 = std::to_string(WorkerThreadCount);
								std::string s1 = std::to_string(RetiredWorkerThreads);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "workerthreadcount", sizeof("workerthreadcount"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "retiredworkerthreads", sizeof("retiredworkerthreads"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								break;
							}
							case 43:
							{
								RtlCopyMemory(ELS->EventName, "WorkerThreadRetirementV2Stop", sizeof("WorkerThreadRetirementV2Stop"));
								auto WorkerThreadCount = safe_parse<uint32_t>(parser, L"WorkerThreadCount");
								auto RetiredWorkerThreads = safe_parse<uint32_t>(parser, L"RetiredWorkerThreads");
								ELS->field.FieldCount = 2;
								std::string s0 = std::to_string(WorkerThreadCount);
								std::string s1 = std::to_string(RetiredWorkerThreads);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "workerthreadcount", sizeof("workerthreadcount"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "retiredworkerthreads", sizeof("retiredworkerthreads"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								break;
							}
							case 44:
							{
								if (schema.event_version() == 0)
								{
									RtlCopyMemory(ELS->EventName, "IOThreadCreationStart", sizeof("IOThreadCreationStart"));
									auto IOThreadCount = safe_parse<uint32_t>(parser, L"IOThreadCount");
									auto RetiredIOThreads = safe_parse<uint32_t>(parser, L"RetiredIOThreads");
									ELS->field.FieldCount = 2;
									std::string s0 = std::to_string(IOThreadCount);
									std::string s1 = std::to_string(RetiredIOThreads);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "iothreadcount", sizeof("iothreadcount"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "retirediothreads", sizeof("retirediothreads"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								}
								else if (schema.event_version() == 1)
								{
									RtlCopyMemory(ELS->EventName, "IOThreadCreationStart_V1", sizeof("IOThreadCreationStart_V1"));
									auto IOThreadCount = safe_parse<uint32_t>(parser, L"IOThreadCount");
									auto RetiredIOThreads = safe_parse<uint32_t>(parser, L"RetiredIOThreads");
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS->field.FieldCount = 3;
									std::string s0 = std::to_string(IOThreadCount);
									std::string s1 = std::to_string(RetiredIOThreads);
									std::string s2 = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "iothreadcount", sizeof("iothreadcount"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "retirediothreads", sizeof("retirediothreads"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								}
								break;
							}
							case 45:
							{
								if (schema.event_version() == 0)
								{
									RtlCopyMemory(ELS->EventName, "IOThreadCreationStop", sizeof("IOThreadCreationStop"));
									auto IOThreadCount = safe_parse<uint32_t>(parser, L"IOThreadCount");
									auto RetiredIOThreads = safe_parse<uint32_t>(parser, L"RetiredIOThreads");
									ELS->field.FieldCount = 2;
									std::string s0 = std::to_string(IOThreadCount);
									std::string s1 = std::to_string(RetiredIOThreads);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "iothreadcount", sizeof("iothreadcount"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "retirediothreads", sizeof("retirediothreads"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								}
								else if (schema.event_version() == 1)
								{
									RtlCopyMemory(ELS->EventName, "IOThreadCreationStop_V1", sizeof("IOThreadCreationStop_V1"));
									auto IOThreadCount = safe_parse<uint32_t>(parser, L"IOThreadCount");
									auto RetiredIOThreads = safe_parse<uint32_t>(parser, L"RetiredIOThreads");
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS->field.FieldCount = 3;
									std::string s0 = std::to_string(IOThreadCount);
									std::string s1 = std::to_string(RetiredIOThreads);
									std::string s2 = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "iothreadcount", sizeof("iothreadcount"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "retirediothreads", sizeof("retirediothreads"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								}
								break;
							}
							case 46:
							{
								if (schema.event_version() == 0)
								{
									RtlCopyMemory(ELS->EventName, "IOThreadRetirementStart", sizeof("IOThreadRetirementStart"));
									auto IOThreadCount = safe_parse<uint32_t>(parser, L"IOThreadCount");
									auto RetiredIOThreads = safe_parse<uint32_t>(parser, L"RetiredIOThreads");
									ELS->field.FieldCount = 2;
									std::string s0 = std::to_string(IOThreadCount);
									std::string s1 = std::to_string(RetiredIOThreads);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "iothreadcount", sizeof("iothreadcount"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "retirediothreads", sizeof("retirediothreads"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								}
								else if (schema.event_version() == 1)
								{
									RtlCopyMemory(ELS->EventName, "IOThreadRetirementStart_V1", sizeof("IOThreadRetirementStart_V1"));
									auto IOThreadCount = safe_parse<uint32_t>(parser, L"IOThreadCount");
									auto RetiredIOThreads = safe_parse<uint32_t>(parser, L"RetiredIOThreads");
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS->field.FieldCount = 3;
									std::string s0 = std::to_string(IOThreadCount);
									std::string s1 = std::to_string(RetiredIOThreads);
									std::string s2 = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "iothreadcount", sizeof("iothreadcount"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "retirediothreads", sizeof("retirediothreads"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								}
								break;
							}
							case 47:
							{
								if (schema.event_version() == 0)
								{
									RtlCopyMemory(ELS->EventName, "IOThreadRetirementStop", sizeof("IOThreadRetirementStop"));
									auto IOThreadCount = safe_parse<uint32_t>(parser, L"IOThreadCount");
									auto RetiredIOThreads = safe_parse<uint32_t>(parser, L"RetiredIOThreads");
									ELS->field.FieldCount = 2;
									std::string s0 = std::to_string(IOThreadCount);
									std::string s1 = std::to_string(RetiredIOThreads);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "iothreadcount", sizeof("iothreadcount"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "retirediothreads", sizeof("retirediothreads"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								}
								else if (schema.event_version() == 1)
								{
									RtlCopyMemory(ELS->EventName, "IOThreadRetirementStop_V1", sizeof("IOThreadRetirementStop_V1"));
									auto IOThreadCount = safe_parse<uint32_t>(parser, L"IOThreadCount");
									auto RetiredIOThreads = safe_parse<uint32_t>(parser, L"RetiredIOThreads");
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS->field.FieldCount = 3;
									std::string s0 = std::to_string(IOThreadCount);
									std::string s1 = std::to_string(RetiredIOThreads);
									std::string s2 = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "iothreadcount", sizeof("iothreadcount"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "retirediothreads", sizeof("retirediothreads"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								}
								break;
							}
							case 48:
							{
								RtlCopyMemory(ELS->EventName, "ThreadpoolSuspensionV2Start", sizeof("ThreadpoolSuspensionV2Start"));
								auto ClrThreadID = safe_parse<uint32_t>(parser, L"ClrThreadID");
								auto CpuUtilization = safe_parse<uint32_t>(parser, L"CpuUtilization");
								ELS->field.FieldCount = 2;
								std::string s0 = std::to_string(ClrThreadID);
								std::string s1 = std::to_string(CpuUtilization);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "clrthreadid", sizeof("clrthreadid"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "cpuutilization", sizeof("cpuutilization"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								break;
							}
							case 49:
							{
								RtlCopyMemory(ELS->EventName, "ThreadpoolSuspensionV2Stop", sizeof("ThreadpoolSuspensionV2Stop"));
								auto ClrThreadID = safe_parse<uint32_t>(parser, L"ClrThreadID");
								auto CpuUtilization = safe_parse<uint32_t>(parser, L"CpuUtilization");
								ELS->field.FieldCount = 2;
								std::string s0 = std::to_string(ClrThreadID);
								std::string s1 = std::to_string(CpuUtilization);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "clrthreadid", sizeof("clrthreadid"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "cpuutilization", sizeof("cpuutilization"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								break;
							}
							case 50:
							{
								RtlCopyMemory(ELS->EventName, "ThreadPoolWorkerThreadStart", sizeof("ThreadPoolWorkerThreadStart"));
								auto ActiveWorkerThreadCount = safe_parse<uint32_t>(parser, L"ActiveWorkerThreadCount");
								auto RetiredWorkerThreadCount = safe_parse<uint32_t>(parser, L"RetiredWorkerThreadCount");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 3;
								std::string s0 = std::to_string(ActiveWorkerThreadCount);
								std::string s1 = std::to_string(RetiredWorkerThreadCount);
								std::string s2 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "activeworkerthreadcount", sizeof("activeworkerthreadcount"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "retiredworkerthreadcount", sizeof("retiredworkerthreadcount"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								break;
							}
							case 51:
							{
								RtlCopyMemory(ELS->EventName, "ThreadPoolWorkerThreadStop", sizeof("ThreadPoolWorkerThreadStop"));
								auto ActiveWorkerThreadCount = safe_parse<uint32_t>(parser, L"ActiveWorkerThreadCount");
								auto RetiredWorkerThreadCount = safe_parse<uint32_t>(parser, L"RetiredWorkerThreadCount");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 3;
								std::string s0 = std::to_string(ActiveWorkerThreadCount);
								std::string s1 = std::to_string(RetiredWorkerThreadCount);
								std::string s2 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "activeworkerthreadcount", sizeof("activeworkerthreadcount"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "retiredworkerthreadcount", sizeof("retiredworkerthreadcount"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								break;
							}
							case 52:
							{
								RtlCopyMemory(ELS->EventName, "ThreadPoolWorkerThreadRetirementStart", sizeof("ThreadPoolWorkerThreadRetirementStart"));
								auto ActiveWorkerThreadCount = safe_parse<uint32_t>(parser, L"ActiveWorkerThreadCount");
								auto RetiredWorkerThreadCount = safe_parse<uint32_t>(parser, L"RetiredWorkerThreadCount");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 3;
								std::string s0 = std::to_string(ActiveWorkerThreadCount);
								std::string s1 = std::to_string(RetiredWorkerThreadCount);
								std::string s2 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "activeworkerthreadcount", sizeof("activeworkerthreadcount"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "retiredworkerthreadcount", sizeof("retiredworkerthreadcount"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								break;
							}
							case 53:
							{
								RtlCopyMemory(ELS->EventName, "ThreadPoolWorkerThreadRetirementStop", sizeof("ThreadPoolWorkerThreadRetirementStop"));
								auto ActiveWorkerThreadCount = safe_parse<uint32_t>(parser, L"ActiveWorkerThreadCount");
								auto RetiredWorkerThreadCount = safe_parse<uint32_t>(parser, L"RetiredWorkerThreadCount");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 3;
								std::string s0 = std::to_string(ActiveWorkerThreadCount);
								std::string s1 = std::to_string(RetiredWorkerThreadCount);
								std::string s2 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "activeworkerthreadcount", sizeof("activeworkerthreadcount"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "retiredworkerthreadcount", sizeof("retiredworkerthreadcount"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								break;
							}
							case 54:
							{
								RtlCopyMemory(ELS->EventName, "ThreadPoolWorkerThreadAdjustmentSample", sizeof("ThreadPoolWorkerThreadAdjustmentSample"));
								auto Throughput = safe_parse<double>(parser, L"Throughput");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 2;
								std::string s0 = std::to_string(Throughput);
								std::string s1 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "throughput", sizeof("throughput"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								break;
							}
							case 55:
							{
								RtlCopyMemory(ELS->EventName, "ThreadPoolWorkerThreadAdjustment", sizeof("ThreadPoolWorkerThreadAdjustment"));
								auto AverageThroughput = safe_parse<double>(parser, L"AverageThroughput");
								auto NewWorkerThreadCount = safe_parse<uint32_t>(parser, L"NewWorkerThreadCount");
								auto Reason = safe_parse<uint32_t>(parser, L"Reason");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 4;
								std::string s0 = std::to_string(AverageThroughput);
								std::string s1 = std::to_string(NewWorkerThreadCount);
								std::string s2 = std::to_string(Reason);
								std::string s3 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "averagethroughput", sizeof("averagethroughput"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "newworkerthreadcount", sizeof("newworkerthreadcount"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "reason", sizeof("reason"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS->field.Fields[3].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
								break;
							}
							case 56:
							{
								RtlCopyMemory(ELS->EventName, "ThreadPoolWorkerThreadAdjustmentStats", sizeof("ThreadPoolWorkerThreadAdjustmentStats"));
								field_idx = 0;
								auto Duration = safe_parse<double>(parser, L"Duration");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "duration", sizeof("duration"));
								std::string s0 = std::to_string(Duration);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s0.c_str(), s0.length());
								auto Throughput = safe_parse<double>(parser, L"Throughput");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "throughput", sizeof("throughput"));
								std::string s1 = std::to_string(Throughput);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s1.c_str(), s1.length());
								auto ThreadWave = safe_parse<double>(parser, L"ThreadWave");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "threadwave", sizeof("threadwave"));
								std::string s2 = std::to_string(ThreadWave);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s2.c_str(), s2.length());
								auto ThroughputWave = safe_parse<double>(parser, L"ThroughputWave");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "throughputwave", sizeof("throughputwave"));
								std::string s3 = std::to_string(ThroughputWave);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s3.c_str(), s3.length());
								auto ThroughputErrorEstimate = safe_parse<double>(parser, L"ThroughputErrorEstimate");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "throughputerrorestimate", sizeof("throughputerrorestimate"));
								std::string s4 = std::to_string(ThroughputErrorEstimate);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s4.c_str(), s4.length());
								auto AverageThroughputErrorEstimate = safe_parse<double>(parser, L"AverageThroughputErrorEstimate");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "averagethroughputerrorestimate", sizeof("averagethroughputerrorestimate"));
								std::string s5 = std::to_string(AverageThroughputErrorEstimate);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s5.c_str(), s5.length());
								auto ThroughputRatio = safe_parse<double>(parser, L"ThroughputRatio");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "throughputratio", sizeof("throughputratio"));
								std::string s6 = std::to_string(ThroughputRatio);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s6.c_str(), s6.length());
								auto Confidence = safe_parse<double>(parser, L"Confidence");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "confidence", sizeof("confidence"));
								std::string s7 = std::to_string(Confidence);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s7.c_str(), s7.length());
								auto NewControlSetting = safe_parse<double>(parser, L"NewControlSetting");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "newcontrolsetting", sizeof("newcontrolsetting"));
								std::string s8 = std::to_string(NewControlSetting);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s8.c_str(), s8.length());
								auto NewThreadWaveMagnitude = safe_parse<uint16_t>(parser, L"NewThreadWaveMagnitude");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "newthreadwavemagnitude", sizeof("newthreadwavemagnitude"));
								std::string s9 = std::to_string(NewThreadWaveMagnitude);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s9.c_str(), s9.length());
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								std::string s10 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s10.c_str(), s10.length());
								ELS->field.FieldCount = field_idx;
								break;
							}
							case 57:
							{
								RtlCopyMemory(ELS->EventName, "ThreadPoolWorkerThreadWait", sizeof("ThreadPoolWorkerThreadWait"));
								auto ActiveWorkerThreadCount = safe_parse<uint32_t>(parser, L"ActiveWorkerThreadCount");
								auto RetiredWorkerThreadCount = safe_parse<uint32_t>(parser, L"RetiredWorkerThreadCount");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 3;
								std::string s0 = std::to_string(ActiveWorkerThreadCount);
								std::string s1 = std::to_string(RetiredWorkerThreadCount);
								std::string s2 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "activeworkerthreadcount", sizeof("activeworkerthreadcount"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "retiredworkerthreadcount", sizeof("retiredworkerthreadcount"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								break;
							}
							case 60:
							{
								RtlCopyMemory(ELS->EventName, "ThreadPoolWorkingThreadCountStart", sizeof("ThreadPoolWorkingThreadCountStart"));
								auto Count = safe_parse<uint32_t>(parser, L"Count");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 2;
								std::string s0 = std::to_string(Count);
								std::string s1 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "count", sizeof("count"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								break;
							}
							case 61:
							{
								RtlCopyMemory(ELS->EventName, "ThreadPoolEnqueue", sizeof("ThreadPoolEnqueue"));
								auto WorkID = safe_parse<uint64_t>(parser, L"WorkID");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 2;
								std::string s0 = std::to_string(WorkID);
								std::string s1 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "workid", sizeof("workid"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								break;
							}
							case 62:
							{
								RtlCopyMemory(ELS->EventName, "ThreadPoolDequeue", sizeof("ThreadPoolDequeue"));
								auto WorkID = safe_parse<uint64_t>(parser, L"WorkID");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 2;
								std::string s0 = std::to_string(WorkID);
								std::string s1 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "workid", sizeof("workid"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								break;
							}
							case 63:
							{
								RtlCopyMemory(ELS->EventName, "ThreadPoolIOEnqueue", sizeof("ThreadPoolIOEnqueue"));
								auto NativeOverlapped = safe_parse<uint64_t>(parser, L"NativeOverlapped");
								auto Overlapped = safe_parse<uint64_t>(parser, L"Overlapped");
								auto MultiDequeues = safe_parse<bool>(parser, L"MultiDequeues");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 4;
								std::string s0 = std::to_string(NativeOverlapped);
								std::string s1 = std::to_string(Overlapped);
								std::string s2 = MultiDequeues ? "true" : "false";
								std::string s3 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "nativeoverlapped", sizeof("nativeoverlapped"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "overlapped", sizeof("overlapped"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "multidequeues", sizeof("multidequeues"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS->field.Fields[3].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
								break;
							}
							case 64:
							{
								RtlCopyMemory(ELS->EventName, "ThreadPoolIODequeue", sizeof("ThreadPoolIODequeue"));
								auto NativeOverlapped = safe_parse<uint64_t>(parser, L"NativeOverlapped");
								auto Overlapped = safe_parse<uint64_t>(parser, L"Overlapped");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 3;
								std::string s0 = std::to_string(NativeOverlapped);
								std::string s1 = std::to_string(Overlapped);
								std::string s2 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "nativeoverlapped", sizeof("nativeoverlapped"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "overlapped", sizeof("overlapped"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								break;
							}
							case 65:
							{
								RtlCopyMemory(ELS->EventName, "ThreadPoolIOPack", sizeof("ThreadPoolIOPack"));
								auto NativeOverlapped = safe_parse<uint64_t>(parser, L"NativeOverlapped");
								auto Overlapped = safe_parse<uint64_t>(parser, L"Overlapped");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 3;
								std::string s0 = std::to_string(NativeOverlapped);
								std::string s1 = std::to_string(Overlapped);
								std::string s2 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "nativeoverlapped", sizeof("nativeoverlapped"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "overlapped", sizeof("overlapped"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								break;
							}
							case 70:
							{
								RtlCopyMemory(ELS->EventName, "ThreadCreating", sizeof("ThreadCreating"));
								auto ID = safe_parse<uint64_t>(parser, L"ID");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 2;
								std::string s0 = std::to_string(ID);
								std::string s1 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "id", sizeof("id"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								break;
							}
							case 71:
							{
								RtlCopyMemory(ELS->EventName, "ThreadRunning", sizeof("ThreadRunning"));
								auto ID = safe_parse<uint64_t>(parser, L"ID");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 2;
								std::string s0 = std::to_string(ID);
								std::string s1 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "id", sizeof("id"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								break;
							}
							case 80:
							{
								if (schema.event_version() == 0)
								{
									RtlCopyMemory(ELS->EventName, "ExceptionStart", sizeof("ExceptionStart"));
									ELS->field.FieldCount = 0;
								}
								else if (schema.event_version() == 1)
								{
									RtlCopyMemory(ELS->EventName, "ExceptionStart_V1", sizeof("ExceptionStart_V1"));
									auto ExceptionType = wchar_to_char((safe_parse<std::wstring>(parser, L"ExceptionType")).c_str());
									auto ExceptionMessage = wchar_to_char((safe_parse<std::wstring>(parser, L"ExceptionMessage")).c_str());
									auto ExceptionEIP = safe_parse<uint64_t>(parser, L"ExceptionEIP");
									auto ExceptionHRESULT = safe_parse<uint32_t>(parser, L"ExceptionHRESULT");
									auto ExceptionFlags = safe_parse<uint16_t>(parser, L"ExceptionFlags");
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS->field.FieldCount = 6;
									std::string s2 = std::to_string(ExceptionEIP);
									std::string s3 = std::to_string(ExceptionHRESULT);
									std::string s4 = std::to_string(ExceptionFlags);
									std::string s5 = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "exceptiontype", sizeof("exceptiontype"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, ExceptionType.c_str(), ExceptionType.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "exceptionmessage", sizeof("exceptionmessage"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, ExceptionMessage.c_str(), ExceptionMessage.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "exceptioneip", sizeof("exceptioneip"));
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
									RtlCopyMemory(ELS->field.Fields[3].FieldName, "exceptionhresult", sizeof("exceptionhresult"));
									RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
									RtlCopyMemory(ELS->field.Fields[4].FieldName, "exceptionflags", sizeof("exceptionflags"));
									RtlCopyMemory(ELS->field.Fields[4].FieldValue, s4.c_str(), s4.length());
									RtlCopyMemory(ELS->field.Fields[5].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									RtlCopyMemory(ELS->field.Fields[5].FieldValue, s5.c_str(), s5.length());
								}
								break;
							}
							case 81:
							{
								if (schema.event_version() == 0)
								{
									RtlCopyMemory(ELS->EventName, "ContentionStart", sizeof("ContentionStart"));
									ELS->field.FieldCount = 0;
								}
								else if (schema.event_version() == 1)
								{
									RtlCopyMemory(ELS->EventName, "ContentionStart_V1", sizeof("ContentionStart_V1"));
									auto ContentionFlags = safe_parse<uint8_t>(parser, L"ContentionFlags");
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS->field.FieldCount = 2;
									std::string s0 = std::to_string(ContentionFlags);
									std::string s1 = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "contentionflags", sizeof("contentionflags"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								}
								break;
							}
							case 82:
							{
								RtlCopyMemory(ELS->EventName, "ClrStackWalk", sizeof("ClrStackWalk"));
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								auto FrameCount = safe_parse<uint32_t>(parser, L"FrameCount");
								auto Stack = safe_parse<uint64_t>(parser, L"Stack");
								ELS->field.FieldCount = 3;
								std::string s0 = std::to_string(ClrInstanceID);
								std::string s1 = std::to_string(FrameCount);
								std::string s2 = std::to_string(Stack);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "framecount", sizeof("framecount"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "stack", sizeof("stack"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								break;
							}
							case 83:
							{
								RtlCopyMemory(ELS->EventName, "AppDomainResourceManagementMemAllocated", sizeof("AppDomainResourceManagementMemAllocated"));
								auto AppDomainID = safe_parse<uint64_t>(parser, L"AppDomainID");
								auto Allocated = safe_parse<uint64_t>(parser, L"Allocated");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 3;
								std::string s0 = std::to_string(AppDomainID);
								std::string s1 = std::to_string(Allocated);
								std::string s2 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "appdomainid", sizeof("appdomainid"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "allocated", sizeof("allocated"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								break;
							}
							case 84:
							{
								RtlCopyMemory(ELS->EventName, "AppDomainResourceManagementMemSurvived", sizeof("AppDomainResourceManagementMemSurvived"));
								auto AppDomainID = safe_parse<uint64_t>(parser, L"AppDomainID");
								auto Survived = safe_parse<uint64_t>(parser, L"Survived");
								auto ProcessSurvived = safe_parse<uint64_t>(parser, L"ProcessSurvived");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 4;
								std::string s0 = std::to_string(AppDomainID);
								std::string s1 = std::to_string(Survived);
								std::string s2 = std::to_string(ProcessSurvived);
								std::string s3 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "appdomainid", sizeof("appdomainid"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "survived", sizeof("survived"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "processsurvived", sizeof("processsurvived"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS->field.Fields[3].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
								break;
							}
							case 85:
							{
								RtlCopyMemory(ELS->EventName, "AppDomainResourceManagementThreadCreated", sizeof("AppDomainResourceManagementThreadCreated"));
								auto ManagedThreadID = safe_parse<uint64_t>(parser, L"ManagedThreadID");
								auto AppDomainID = safe_parse<uint64_t>(parser, L"AppDomainID");
								auto Flags = safe_parse<uint32_t>(parser, L"Flags");
								auto ManagedThreadIndex = safe_parse<uint32_t>(parser, L"ManagedThreadIndex");
								auto OSThreadID = safe_parse<uint32_t>(parser, L"OSThreadID");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 6;
								std::string s0 = std::to_string(ManagedThreadID);
								std::string s1 = std::to_string(AppDomainID);
								std::string s2 = std::to_string(Flags);
								std::string s3 = std::to_string(ManagedThreadIndex);
								std::string s4 = std::to_string(OSThreadID);
								std::string s5 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "managedthreadid", sizeof("managedthreadid"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "appdomainid", sizeof("appdomainid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "flags", sizeof("flags"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS->field.Fields[3].FieldName, "managedthreadindex", sizeof("managedthreadindex"));
								RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
								RtlCopyMemory(ELS->field.Fields[4].FieldName, "osthreadid", sizeof("osthreadid"));
								RtlCopyMemory(ELS->field.Fields[4].FieldValue, s4.c_str(), s4.length());
								RtlCopyMemory(ELS->field.Fields[5].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[5].FieldValue, s5.c_str(), s5.length());
								break;
							}
							case 86:
							{
								RtlCopyMemory(ELS->EventName, "AppDomainResourceManagementThreadTerminated", sizeof("AppDomainResourceManagementThreadTerminated"));
								auto ManagedThreadID = safe_parse<uint64_t>(parser, L"ManagedThreadID");
								auto AppDomainID = safe_parse<uint64_t>(parser, L"AppDomainID");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 3;
								std::string s0 = std::to_string(ManagedThreadID);
								std::string s1 = std::to_string(AppDomainID);
								std::string s2 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "managedthreadid", sizeof("managedthreadid"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "appdomainid", sizeof("appdomainid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								break;
							}
							case 87:
							{
								RtlCopyMemory(ELS->EventName, "AppDomainResourceManagementDomainEnter", sizeof("AppDomainResourceManagementDomainEnter"));
								auto ManagedThreadID = safe_parse<uint64_t>(parser, L"ManagedThreadID");
								auto AppDomainID = safe_parse<uint64_t>(parser, L"AppDomainID");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 3;
								std::string s0 = std::to_string(ManagedThreadID);
								std::string s1 = std::to_string(AppDomainID);
								std::string s2 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "managedthreadid", sizeof("managedthreadid"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "appdomainid", sizeof("appdomainid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								break;
							}
							case 88:
							{
								RtlCopyMemory(ELS->EventName, "ILStubStubGenerated", sizeof("ILStubStubGenerated"));
								field_idx = 0;
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								std::string s0 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s0.c_str(), s0.length());
								auto ModuleID = safe_parse<uint64_t>(parser, L"ModuleID");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "moduleid", sizeof("moduleid"));
								std::string s1 = std::to_string(ModuleID);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s1.c_str(), s1.length());
								auto StubMethodID = safe_parse<uint64_t>(parser, L"StubMethodID");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "stubmethodid", sizeof("stubmethodid"));
								std::string s2 = std::to_string(StubMethodID);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s2.c_str(), s2.length());
								auto StubFlags = safe_parse<uint32_t>(parser, L"StubFlags");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "stubflags", sizeof("stubflags"));
								std::string s3 = std::to_string(StubFlags);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s3.c_str(), s3.length());
								auto ManagedInteropMethodToken = safe_parse<uint32_t>(parser, L"ManagedInteropMethodToken");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "managedinteropmethodtoken", sizeof("managedinteropmethodtoken"));
								std::string s4 = std::to_string(ManagedInteropMethodToken);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s4.c_str(), s4.length());
								auto ManagedInteropMethodNamespace = wchar_to_char((safe_parse<std::wstring>(parser, L"ManagedInteropMethodNamespace")).c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "managedinteropmethodnamespace", sizeof("managedinteropmethodnamespace"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, ManagedInteropMethodNamespace.c_str(), ManagedInteropMethodNamespace.length());
								auto ManagedInteropMethodName = wchar_to_char((safe_parse<std::wstring>(parser, L"ManagedInteropMethodName")).c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "managedinteropmethodname", sizeof("managedinteropmethodname"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, ManagedInteropMethodName.c_str(), ManagedInteropMethodName.length());
								auto ManagedInteropMethodSignature = wchar_to_char((safe_parse<std::wstring>(parser, L"ManagedInteropMethodSignature")).c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "managedinteropmethodsignature", sizeof("managedinteropmethodsignature"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, ManagedInteropMethodSignature.c_str(), ManagedInteropMethodSignature.length());
								ELS->field.FieldCount = field_idx;
								break;
							}
							case 89:
							{
								RtlCopyMemory(ELS->EventName, "ILStubStubCacheHit", sizeof("ILStubStubCacheHit"));
								field_idx = 0;
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								std::string s0 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s0.c_str(), s0.length());
								auto ModuleID = safe_parse<uint64_t>(parser, L"ModuleID");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "moduleid", sizeof("moduleid"));
								std::string s1 = std::to_string(ModuleID);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s1.c_str(), s1.length());
								auto StubMethodID = safe_parse<uint64_t>(parser, L"StubMethodID");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "stubmethodid", sizeof("stubmethodid"));
								std::string s2 = std::to_string(StubMethodID);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s2.c_str(), s2.length());
								auto ManagedInteropMethodToken = safe_parse<uint32_t>(parser, L"ManagedInteropMethodToken");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "managedinteropmethodtoken", sizeof("managedinteropmethodtoken"));
								std::string s3 = std::to_string(ManagedInteropMethodToken);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s3.c_str(), s3.length());
								auto ManagedInteropMethodNamespace = wchar_to_char((safe_parse<std::wstring>(parser, L"ManagedInteropMethodNamespace")).c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "managedinteropmethodnamespace", sizeof("managedinteropmethodnamespace"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, ManagedInteropMethodNamespace.c_str(), ManagedInteropMethodNamespace.length());
								auto ManagedInteropMethodName = wchar_to_char((safe_parse<std::wstring>(parser, L"ManagedInteropMethodName")).c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "managedinteropmethodname", sizeof("managedinteropmethodname"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, ManagedInteropMethodName.c_str(), ManagedInteropMethodName.length());
								auto ManagedInteropMethodSignature = wchar_to_char((safe_parse<std::wstring>(parser, L"ManagedInteropMethodSignature")).c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "managedinteropmethodsignature", sizeof("managedinteropmethodsignature"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, ManagedInteropMethodSignature.c_str(), ManagedInteropMethodSignature.length());
								ELS->field.FieldCount = field_idx;
								break;
							}
							case 91:
							{
								RtlCopyMemory(ELS->EventName, "ContentionStop", sizeof("ContentionStop"));
								auto ContentionFlags = safe_parse<uint8_t>(parser, L"ContentionFlags");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 2;
								std::string s0 = std::to_string(ContentionFlags);
								std::string s1 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "contentionflags", sizeof("contentionflags"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								break;
							}
							case 137:
							case 138:
							{
								// These event IDs share the same template but have different names
								if (schema.event_id() == 137)
									RtlCopyMemory(ELS->EventName, "MethodDCStartV2", sizeof("MethodDCStartV2"));
								else
									RtlCopyMemory(ELS->EventName, "MethodDCStopV2", sizeof("MethodDCStopV2"));

								auto MethodID = safe_parse<uint64_t>(parser, L"MethodID");
								auto ModuleID = safe_parse<uint64_t>(parser, L"ModuleID");
								auto MethodStartAddress = safe_parse<uint64_t>(parser, L"MethodStartAddress");
								auto MethodSize = safe_parse<uint32_t>(parser, L"MethodSize");
								auto MethodToken = safe_parse<uint32_t>(parser, L"MethodToken");
								auto MethodFlags = safe_parse<uint32_t>(parser, L"MethodFlags");
								ELS->field.FieldCount = 6;
								std::string s0 = std::to_string(MethodID);
								std::string s1 = std::to_string(ModuleID);
								std::string s2 = std::to_string(MethodStartAddress);
								std::string s3 = std::to_string(MethodSize);
								std::string s4 = std::to_string(MethodToken);
								std::string s5 = std::to_string(MethodFlags);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "methodid", sizeof("methodid"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "moduleid", sizeof("moduleid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "methodstartaddress", sizeof("methodstartaddress"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS->field.Fields[3].FieldName, "methodsize", sizeof("methodsize"));
								RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
								RtlCopyMemory(ELS->field.Fields[4].FieldName, "methodtoken", sizeof("methodtoken"));
								RtlCopyMemory(ELS->field.Fields[4].FieldValue, s4.c_str(), s4.length());
								RtlCopyMemory(ELS->field.Fields[5].FieldName, "methodflags", sizeof("methodflags"));
								RtlCopyMemory(ELS->field.Fields[5].FieldValue, s5.c_str(), s5.length());
								break;
							}
							case 139:
							case 140:
							{
								if (schema.event_id() == 139)
									RtlCopyMemory(ELS->EventName, "MethodDCStartVerboseV2", sizeof("MethodDCStartVerboseV2"));
								else
									RtlCopyMemory(ELS->EventName, "MethodDCStopVerboseV2", sizeof("MethodDCStopVerboseV2"));

								auto MethodID = safe_parse<uint64_t>(parser, L"MethodID");
								auto ModuleID = safe_parse<uint64_t>(parser, L"ModuleID");
								auto MethodStartAddress = safe_parse<uint64_t>(parser, L"MethodStartAddress");
								auto MethodSize = safe_parse<uint32_t>(parser, L"MethodSize");
								auto MethodToken = safe_parse<uint32_t>(parser, L"MethodToken");
								auto MethodFlags = safe_parse<uint32_t>(parser, L"MethodFlags");
								auto MethodNamespace = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodNamespace").c_str());
								auto MethodName = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodName").c_str());
								auto MethodSignature = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodSignature").c_str());
								ELS->field.FieldCount = 9;
								std::string s0 = std::to_string(MethodID);
								std::string s1 = std::to_string(ModuleID);
								std::string s2 = std::to_string(MethodStartAddress);
								std::string s3 = std::to_string(MethodSize);
								std::string s4 = std::to_string(MethodToken);
								std::string s5 = std::to_string(MethodFlags);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "methodid", sizeof("methodid"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "moduleid", sizeof("moduleid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "methodstartaddress", sizeof("methodstartaddress"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS->field.Fields[3].FieldName, "methodsize", sizeof("methodsize"));
								RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
								RtlCopyMemory(ELS->field.Fields[4].FieldName, "methodtoken", sizeof("methodtoken"));
								RtlCopyMemory(ELS->field.Fields[4].FieldValue, s4.c_str(), s4.length());
								RtlCopyMemory(ELS->field.Fields[5].FieldName, "methodflags", sizeof("methodflags"));
								RtlCopyMemory(ELS->field.Fields[5].FieldValue, s5.c_str(), s5.length());
								RtlCopyMemory(ELS->field.Fields[6].FieldName, "methodnamespace", sizeof("methodnamespace"));
								RtlCopyMemory(ELS->field.Fields[6].FieldValue, MethodNamespace.c_str(), MethodNamespace.length());
								RtlCopyMemory(ELS->field.Fields[7].FieldName, "methodname", sizeof("methodname"));
								RtlCopyMemory(ELS->field.Fields[7].FieldValue, MethodName.c_str(), MethodName.length());
								RtlCopyMemory(ELS->field.Fields[8].FieldName, "methodsignature", sizeof("methodsignature"));
								RtlCopyMemory(ELS->field.Fields[8].FieldValue, MethodSignature.c_str(), MethodSignature.length());
								break;
							}
							case 141:
							case 142:
							{
								if (schema.event_version() == 0)
								{
									if (schema.event_id() == 141) RtlCopyMemory(ELS->EventName, "MethodLoad", sizeof("MethodLoad"));
									else RtlCopyMemory(ELS->EventName, "MethodUnload", sizeof("MethodUnload"));

									auto MethodID = safe_parse<uint64_t>(parser, L"MethodID");
									auto ModuleID = safe_parse<uint64_t>(parser, L"ModuleID");
									auto MethodStartAddress = safe_parse<uint64_t>(parser, L"MethodStartAddress");
									auto MethodSize = safe_parse<uint32_t>(parser, L"MethodSize");
									auto MethodToken = safe_parse<uint32_t>(parser, L"MethodToken");
									auto MethodFlags = safe_parse<uint32_t>(parser, L"MethodFlags");
									ELS->field.FieldCount = 6;
									std::string s0 = std::to_string(MethodID);
									std::string s1 = std::to_string(ModuleID);
									std::string s2 = std::to_string(MethodStartAddress);
									std::string s3 = std::to_string(MethodSize);
									std::string s4 = std::to_string(MethodToken);
									std::string s5 = std::to_string(MethodFlags);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "methodid", sizeof("methodid"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "moduleid", sizeof("moduleid"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "methodstartaddress", sizeof("methodstartaddress"));
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
									RtlCopyMemory(ELS->field.Fields[3].FieldName, "methodsize", sizeof("methodsize"));
									RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
									RtlCopyMemory(ELS->field.Fields[4].FieldName, "methodtoken", sizeof("methodtoken"));
									RtlCopyMemory(ELS->field.Fields[4].FieldValue, s4.c_str(), s4.length());
									RtlCopyMemory(ELS->field.Fields[5].FieldName, "methodflags", sizeof("methodflags"));
									RtlCopyMemory(ELS->field.Fields[5].FieldValue, s5.c_str(), s5.length());
								}
								else if (schema.event_version() == 1)
								{
									if (schema.event_id() == 141) RtlCopyMemory(ELS->EventName, "MethodLoad_V1", sizeof("MethodLoad_V1"));
									else RtlCopyMemory(ELS->EventName, "MethodUnload_V1", sizeof("MethodUnload_V1"));

									auto MethodID = safe_parse<uint64_t>(parser, L"MethodID");
									auto ModuleID = safe_parse<uint64_t>(parser, L"ModuleID");
									auto MethodStartAddress = safe_parse<uint64_t>(parser, L"MethodStartAddress");
									auto MethodSize = safe_parse<uint32_t>(parser, L"MethodSize");
									auto MethodToken = safe_parse<uint32_t>(parser, L"MethodToken");
									auto MethodFlags = safe_parse<uint32_t>(parser, L"MethodFlags");
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS->field.FieldCount = 7;
									std::string s0 = std::to_string(MethodID);
									std::string s1 = std::to_string(ModuleID);
									std::string s2 = std::to_string(MethodStartAddress);
									std::string s3 = std::to_string(MethodSize);
									std::string s4 = std::to_string(MethodToken);
									std::string s5 = std::to_string(MethodFlags);
									std::string s6 = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "methodid", sizeof("methodid"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "moduleid", sizeof("moduleid"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "methodstartaddress", sizeof("methodstartaddress"));
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
									RtlCopyMemory(ELS->field.Fields[3].FieldName, "methodsize", sizeof("methodsize"));
									RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
									RtlCopyMemory(ELS->field.Fields[4].FieldName, "methodtoken", sizeof("methodtoken"));
									RtlCopyMemory(ELS->field.Fields[4].FieldValue, s4.c_str(), s4.length());
									RtlCopyMemory(ELS->field.Fields[5].FieldName, "methodflags", sizeof("methodflags"));
									RtlCopyMemory(ELS->field.Fields[5].FieldValue, s5.c_str(), s5.length());
									RtlCopyMemory(ELS->field.Fields[6].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									RtlCopyMemory(ELS->field.Fields[6].FieldValue, s6.c_str(), s6.length());
								}
								else if (schema.event_version() == 2)
								{
									if (schema.event_id() == 141) RtlCopyMemory(ELS->EventName, "MethodLoad_V2", sizeof("MethodLoad_V2"));
									else RtlCopyMemory(ELS->EventName, "MethodUnload_V2", sizeof("MethodUnload_V2"));

									auto MethodID = safe_parse<uint64_t>(parser, L"MethodID");
									auto ModuleID = safe_parse<uint64_t>(parser, L"ModuleID");
									auto MethodStartAddress = safe_parse<uint64_t>(parser, L"MethodStartAddress");
									auto MethodSize = safe_parse<uint32_t>(parser, L"MethodSize");
									auto MethodToken = safe_parse<uint32_t>(parser, L"MethodToken");
									auto MethodFlags = safe_parse<uint32_t>(parser, L"MethodFlags");
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									auto ReJITID = safe_parse<uint64_t>(parser, L"ReJITID");
									ELS->field.FieldCount = 8;
									std::string s0 = std::to_string(MethodID);
									std::string s1 = std::to_string(ModuleID);
									std::string s2 = std::to_string(MethodStartAddress);
									std::string s3 = std::to_string(MethodSize);
									std::string s4 = std::to_string(MethodToken);
									std::string s5 = std::to_string(MethodFlags);
									std::string s6 = std::to_string(ClrInstanceID);
									std::string s7 = std::to_string(ReJITID);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "methodid", sizeof("methodid"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "moduleid", sizeof("moduleid"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "methodstartaddress", sizeof("methodstartaddress"));
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
									RtlCopyMemory(ELS->field.Fields[3].FieldName, "methodsize", sizeof("methodsize"));
									RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
									RtlCopyMemory(ELS->field.Fields[4].FieldName, "methodtoken", sizeof("methodtoken"));
									RtlCopyMemory(ELS->field.Fields[4].FieldValue, s4.c_str(), s4.length());
									RtlCopyMemory(ELS->field.Fields[5].FieldName, "methodflags", sizeof("methodflags"));
									RtlCopyMemory(ELS->field.Fields[5].FieldValue, s5.c_str(), s5.length());
									RtlCopyMemory(ELS->field.Fields[6].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									RtlCopyMemory(ELS->field.Fields[6].FieldValue, s6.c_str(), s6.length());
									RtlCopyMemory(ELS->field.Fields[7].FieldName, "rejitid", sizeof("rejitid"));
									RtlCopyMemory(ELS->field.Fields[7].FieldValue, s7.c_str(), s7.length());
								}
								break;
							}
							case 143:
							case 144:
							{
								if (schema.event_version() == 0)
								{
									if (schema.event_id() == 143) RtlCopyMemory(ELS->EventName, "MethodLoadVerbose", sizeof("MethodLoadVerbose"));
									else RtlCopyMemory(ELS->EventName, "MethodUnloadVerbose", sizeof("MethodUnloadVerbose"));

									auto MethodID = safe_parse<uint64_t>(parser, L"MethodID");
									auto ModuleID = safe_parse<uint64_t>(parser, L"ModuleID");
									auto MethodStartAddress = safe_parse<uint64_t>(parser, L"MethodStartAddress");
									auto MethodSize = safe_parse<uint32_t>(parser, L"MethodSize");
									auto MethodToken = safe_parse<uint32_t>(parser, L"MethodToken");
									auto MethodFlags = safe_parse<uint32_t>(parser, L"MethodFlags");
									auto MethodNamespace = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodNamespace").c_str());
									auto MethodName = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodName").c_str());
									auto MethodSignature = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodSignature").c_str());
									ELS->field.FieldCount = 9;
									std::string s0 = std::to_string(MethodID);
									std::string s1 = std::to_string(ModuleID);
									std::string s2 = std::to_string(MethodStartAddress);
									std::string s3 = std::to_string(MethodSize);
									std::string s4 = std::to_string(MethodToken);
									std::string s5 = std::to_string(MethodFlags);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "methodid", sizeof("methodid"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "moduleid", sizeof("moduleid"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "methodstartaddress", sizeof("methodstartaddress"));
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
									RtlCopyMemory(ELS->field.Fields[3].FieldName, "methodsize", sizeof("methodsize"));
									RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
									RtlCopyMemory(ELS->field.Fields[4].FieldName, "methodtoken", sizeof("methodtoken"));
									RtlCopyMemory(ELS->field.Fields[4].FieldValue, s4.c_str(), s4.length());
									RtlCopyMemory(ELS->field.Fields[5].FieldName, "methodflags", sizeof("methodflags"));
									RtlCopyMemory(ELS->field.Fields[5].FieldValue, s5.c_str(), s5.length());
									RtlCopyMemory(ELS->field.Fields[6].FieldName, "methodnamespace", sizeof("methodnamespace"));
									RtlCopyMemory(ELS->field.Fields[6].FieldValue, MethodNamespace.c_str(), MethodNamespace.length());
									RtlCopyMemory(ELS->field.Fields[7].FieldName, "methodname", sizeof("methodname"));
									RtlCopyMemory(ELS->field.Fields[7].FieldValue, MethodName.c_str(), MethodName.length());
									RtlCopyMemory(ELS->field.Fields[8].FieldName, "methodsignature", sizeof("methodsignature"));
									RtlCopyMemory(ELS->field.Fields[8].FieldValue, MethodSignature.c_str(), MethodSignature.length());
								}
								else if (schema.event_version() == 1)
								{
									if (schema.event_id() == 143) RtlCopyMemory(ELS->EventName, "MethodLoadVerbose_V1", sizeof("MethodLoadVerbose_V1"));
									else RtlCopyMemory(ELS->EventName, "MethodUnloadVerbose_V1", sizeof("MethodUnloadVerbose_V1"));

									auto MethodID = safe_parse<uint64_t>(parser, L"MethodID");
									auto ModuleID = safe_parse<uint64_t>(parser, L"ModuleID");
									auto MethodStartAddress = safe_parse<uint64_t>(parser, L"MethodStartAddress");
									auto MethodSize = safe_parse<uint32_t>(parser, L"MethodSize");
									auto MethodToken = safe_parse<uint32_t>(parser, L"MethodToken");
									auto MethodFlags = safe_parse<uint32_t>(parser, L"MethodFlags");
									auto MethodNamespace = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodNamespace").c_str());
									auto MethodName = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodName").c_str());
									auto MethodSignature = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodSignature").c_str());
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS->field.FieldCount = 10;
									std::string s0 = std::to_string(MethodID);
									std::string s1 = std::to_string(ModuleID);
									std::string s2 = std::to_string(MethodStartAddress);
									std::string s3 = std::to_string(MethodSize);
									std::string s4 = std::to_string(MethodToken);
									std::string s5 = std::to_string(MethodFlags);
									std::string s9 = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "methodid", sizeof("methodid"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "moduleid", sizeof("moduleid"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "methodstartaddress", sizeof("methodstartaddress"));
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
									RtlCopyMemory(ELS->field.Fields[3].FieldName, "methodsize", sizeof("methodsize"));
									RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
									RtlCopyMemory(ELS->field.Fields[4].FieldName, "methodtoken", sizeof("methodtoken"));
									RtlCopyMemory(ELS->field.Fields[4].FieldValue, s4.c_str(), s4.length());
									RtlCopyMemory(ELS->field.Fields[5].FieldName, "methodflags", sizeof("methodflags"));
									RtlCopyMemory(ELS->field.Fields[5].FieldValue, s5.c_str(), s5.length());
									RtlCopyMemory(ELS->field.Fields[6].FieldName, "methodnamespace", sizeof("methodnamespace"));
									RtlCopyMemory(ELS->field.Fields[6].FieldValue, MethodNamespace.c_str(), MethodNamespace.length());
									RtlCopyMemory(ELS->field.Fields[7].FieldName, "methodname", sizeof("methodname"));
									RtlCopyMemory(ELS->field.Fields[7].FieldValue, MethodName.c_str(), MethodName.length());
									RtlCopyMemory(ELS->field.Fields[8].FieldName, "methodsignature", sizeof("methodsignature"));
									RtlCopyMemory(ELS->field.Fields[8].FieldValue, MethodSignature.c_str(), MethodSignature.length());
									RtlCopyMemory(ELS->field.Fields[9].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									RtlCopyMemory(ELS->field.Fields[9].FieldValue, s9.c_str(), s9.length());
								}
								else if (schema.event_version() == 2)
								{
									if (schema.event_id() == 143) RtlCopyMemory(ELS->EventName, "MethodLoadVerbose_V2", sizeof("MethodLoadVerbose_V2"));
									else RtlCopyMemory(ELS->EventName, "MethodUnloadVerbose_V2", sizeof("MethodUnloadVerbose_V2"));

									auto MethodID = safe_parse<uint64_t>(parser, L"MethodID");
									auto ModuleID = safe_parse<uint64_t>(parser, L"ModuleID");
									auto MethodStartAddress = safe_parse<uint64_t>(parser, L"MethodStartAddress");
									auto MethodSize = safe_parse<uint32_t>(parser, L"MethodSize");
									auto MethodToken = safe_parse<uint32_t>(parser, L"MethodToken");
									auto MethodFlags = safe_parse<uint32_t>(parser, L"MethodFlags");
									auto MethodNamespace = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodNamespace").c_str());
									auto MethodName = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodName").c_str());
									auto MethodSignature = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodSignature").c_str());
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									auto ReJITID = safe_parse<uint64_t>(parser, L"ReJITID");
									ELS->field.FieldCount = 11;
									std::string s0 = std::to_string(MethodID);
									std::string s1 = std::to_string(ModuleID);
									std::string s2 = std::to_string(MethodStartAddress);
									std::string s3 = std::to_string(MethodSize);
									std::string s4 = std::to_string(MethodToken);
									std::string s5 = std::to_string(MethodFlags);
									std::string s9 = std::to_string(ClrInstanceID);
									std::string s10 = std::to_string(ReJITID);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "methodid", sizeof("methodid"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "moduleid", sizeof("moduleid"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "methodstartaddress", sizeof("methodstartaddress"));
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
									RtlCopyMemory(ELS->field.Fields[3].FieldName, "methodsize", sizeof("methodsize"));
									RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
									RtlCopyMemory(ELS->field.Fields[4].FieldName, "methodtoken", sizeof("methodtoken"));
									RtlCopyMemory(ELS->field.Fields[4].FieldValue, s4.c_str(), s4.length());
									RtlCopyMemory(ELS->field.Fields[5].FieldName, "methodflags", sizeof("methodflags"));
									RtlCopyMemory(ELS->field.Fields[5].FieldValue, s5.c_str(), s5.length());
									RtlCopyMemory(ELS->field.Fields[6].FieldName, "methodnamespace", sizeof("methodnamespace"));
									RtlCopyMemory(ELS->field.Fields[6].FieldValue, MethodNamespace.c_str(), MethodNamespace.length());
									RtlCopyMemory(ELS->field.Fields[7].FieldName, "methodname", sizeof("methodname"));
									RtlCopyMemory(ELS->field.Fields[7].FieldValue, MethodName.c_str(), MethodName.length());
									RtlCopyMemory(ELS->field.Fields[8].FieldName, "methodsignature", sizeof("methodsignature"));
									RtlCopyMemory(ELS->field.Fields[8].FieldValue, MethodSignature.c_str(), MethodSignature.length());
									RtlCopyMemory(ELS->field.Fields[9].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									RtlCopyMemory(ELS->field.Fields[9].FieldValue, s9.c_str(), s9.length());
									RtlCopyMemory(ELS->field.Fields[10].FieldName, "rejitid", sizeof("rejitid"));
									RtlCopyMemory(ELS->field.Fields[10].FieldValue, s10.c_str(), s10.length());
								}
								break;
							}
							case 145:
							{
								if (schema.event_version() == 0)
								{
									RtlCopyMemory(ELS->EventName, "MethodJittingStarted", sizeof("MethodJittingStarted"));
									auto MethodID = safe_parse<uint64_t>(parser, L"MethodID");
									auto ModuleID = safe_parse<uint64_t>(parser, L"ModuleID");
									auto MethodToken = safe_parse<uint32_t>(parser, L"MethodToken");
									auto MethodILSize = safe_parse<uint32_t>(parser, L"MethodILSize");
									auto MethodNamespace = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodNamespace").c_str());
									auto MethodName = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodName").c_str());
									auto MethodSignature = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodSignature").c_str());
									ELS->field.FieldCount = 7;
									std::string s0 = std::to_string(MethodID);
									std::string s1 = std::to_string(ModuleID);
									std::string s2 = std::to_string(MethodToken);
									std::string s3 = std::to_string(MethodILSize);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "methodid", sizeof("methodid"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "moduleid", sizeof("moduleid"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "methodtoken", sizeof("methodtoken"));
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
									RtlCopyMemory(ELS->field.Fields[3].FieldName, "methodilsize", sizeof("methodilsize"));
									RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
									RtlCopyMemory(ELS->field.Fields[4].FieldName, "methodnamespace", sizeof("methodnamespace"));
									RtlCopyMemory(ELS->field.Fields[4].FieldValue, MethodNamespace.c_str(), MethodNamespace.length());
									RtlCopyMemory(ELS->field.Fields[5].FieldName, "methodname", sizeof("methodname"));
									RtlCopyMemory(ELS->field.Fields[5].FieldValue, MethodName.c_str(), MethodName.length());
									RtlCopyMemory(ELS->field.Fields[6].FieldName, "methodsignature", sizeof("methodsignature"));
									RtlCopyMemory(ELS->field.Fields[6].FieldValue, MethodSignature.c_str(), MethodSignature.length());
								}
								else if (schema.event_version() == 1)
								{
									RtlCopyMemory(ELS->EventName, "MethodJittingStarted_V1", sizeof("MethodJittingStarted_V1"));
									auto MethodID = safe_parse<uint64_t>(parser, L"MethodID");
									auto ModuleID = safe_parse<uint64_t>(parser, L"ModuleID");
									auto MethodToken = safe_parse<uint32_t>(parser, L"MethodToken");
									auto MethodILSize = safe_parse<uint32_t>(parser, L"MethodILSize");
									auto MethodNamespace = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodNamespace").c_str());
									auto MethodName = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodName").c_str());
									auto MethodSignature = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodSignature").c_str());
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS->field.FieldCount = 8;
									std::string s0 = std::to_string(MethodID);
									std::string s1 = std::to_string(ModuleID);
									std::string s2 = std::to_string(MethodToken);
									std::string s3 = std::to_string(MethodILSize);
									std::string s7 = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "methodid", sizeof("methodid"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "moduleid", sizeof("moduleid"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "methodtoken", sizeof("methodtoken"));
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
									RtlCopyMemory(ELS->field.Fields[3].FieldName, "methodilsize", sizeof("methodilsize"));
									RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
									RtlCopyMemory(ELS->field.Fields[4].FieldName, "methodnamespace", sizeof("methodnamespace"));
									RtlCopyMemory(ELS->field.Fields[4].FieldValue, MethodNamespace.c_str(), MethodNamespace.length());
									RtlCopyMemory(ELS->field.Fields[5].FieldName, "methodname", sizeof("methodname"));
									RtlCopyMemory(ELS->field.Fields[5].FieldValue, MethodName.c_str(), MethodName.length());
									RtlCopyMemory(ELS->field.Fields[6].FieldName, "methodsignature", sizeof("methodsignature"));
									RtlCopyMemory(ELS->field.Fields[6].FieldValue, MethodSignature.c_str(), MethodSignature.length());
									RtlCopyMemory(ELS->field.Fields[7].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									RtlCopyMemory(ELS->field.Fields[7].FieldValue, s7.c_str(), s7.length());
								}
								break;
							}
							case 149:
							{
								RtlCopyMemory(ELS->EventName, "LoaderModuleDCStartV2", sizeof("LoaderModuleDCStartV2"));
								auto ModuleID = safe_parse<uint64_t>(parser, L"ModuleID");
								auto AssemblyID = safe_parse<uint64_t>(parser, L"AssemblyID");
								auto ModuleFlags = safe_parse<uint32_t>(parser, L"ModuleFlags");
								auto ModuleILPath = wchar_to_char(safe_parse<std::wstring>(parser, L"ModuleILPath").c_str());
								auto ModuleNativePath = wchar_to_char(safe_parse<std::wstring>(parser, L"ModuleNativePath").c_str());
								ELS->field.FieldCount = 5;
								std::string s0 = std::to_string(ModuleID);
								std::string s1 = std::to_string(AssemblyID);
								std::string s2 = std::to_string(ModuleFlags);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "moduleid", sizeof("moduleid"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "assemblyid", sizeof("assemblyid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "moduleflags", sizeof("moduleflags"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS->field.Fields[3].FieldName, "moduleilpath", sizeof("moduleilpath"));
								RtlCopyMemory(ELS->field.Fields[3].FieldValue, ModuleILPath.c_str(), ModuleILPath.length());
								RtlCopyMemory(ELS->field.Fields[4].FieldName, "modulenativepath", sizeof("modulenativepath"));
								RtlCopyMemory(ELS->field.Fields[4].FieldValue, ModuleNativePath.c_str(), ModuleNativePath.length());
								break;
							}
							case 150:
							{
								RtlCopyMemory(ELS->EventName, "LoaderModuleDCStopV2", sizeof("LoaderModuleDCStopV2"));
								auto ModuleID = safe_parse<uint64_t>(parser, L"ModuleID");
								auto AssemblyID = safe_parse<uint64_t>(parser, L"AssemblyID");
								auto ModuleFlags = safe_parse<uint32_t>(parser, L"ModuleFlags");
								auto ModuleILPath = wchar_to_char(safe_parse<std::wstring>(parser, L"ModuleILPath").c_str());
								auto ModuleNativePath = wchar_to_char(safe_parse<std::wstring>(parser, L"ModuleNativePath").c_str());
								ELS->field.FieldCount = 5;
								std::string s0 = std::to_string(ModuleID);
								std::string s1 = std::to_string(AssemblyID);
								std::string s2 = std::to_string(ModuleFlags);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "moduleid", sizeof("moduleid"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "assemblyid", sizeof("assemblyid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "moduleflags", sizeof("moduleflags"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS->field.Fields[3].FieldName, "moduleilpath", sizeof("moduleilpath"));
								RtlCopyMemory(ELS->field.Fields[3].FieldValue, ModuleILPath.c_str(), ModuleILPath.length());
								RtlCopyMemory(ELS->field.Fields[4].FieldName, "modulenativepath", sizeof("modulenativepath"));
								RtlCopyMemory(ELS->field.Fields[4].FieldValue, ModuleNativePath.c_str(), ModuleNativePath.length());
								break;
							}
							case 151:
							{
								if (schema.event_version() == 0)
								{
									RtlCopyMemory(ELS->EventName, "LoaderDomainModuleLoad", sizeof("LoaderDomainModuleLoad"));
									auto ModuleID = safe_parse<uint64_t>(parser, L"ModuleID");
									auto AssemblyID = safe_parse<uint64_t>(parser, L"AssemblyID");
									auto AppDomainID = safe_parse<uint64_t>(parser, L"AppDomainID");
									auto ModuleFlags = safe_parse<uint32_t>(parser, L"ModuleFlags");
									auto ModuleILPath = wchar_to_char(safe_parse<std::wstring>(parser, L"ModuleILPath").c_str());
									auto ModuleNativePath = wchar_to_char(safe_parse<std::wstring>(parser, L"ModuleNativePath").c_str());
									ELS->field.FieldCount = 6;
									std::string s0 = std::to_string(ModuleID);
									std::string s1 = std::to_string(AssemblyID);
									std::string s2 = std::to_string(AppDomainID);
									std::string s3 = std::to_string(ModuleFlags);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "moduleid", sizeof("moduleid"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "assemblyid", sizeof("assemblyid"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "appdomainid", sizeof("appdomainid"));
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
									RtlCopyMemory(ELS->field.Fields[3].FieldName, "moduleflags", sizeof("moduleflags"));
									RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
									RtlCopyMemory(ELS->field.Fields[4].FieldName, "moduleilpath", sizeof("moduleilpath"));
									RtlCopyMemory(ELS->field.Fields[4].FieldValue, ModuleILPath.c_str(), ModuleILPath.length());
									RtlCopyMemory(ELS->field.Fields[5].FieldName, "modulenativepath", sizeof("modulenativepath"));
									RtlCopyMemory(ELS->field.Fields[5].FieldValue, ModuleNativePath.c_str(), ModuleNativePath.length());
								}
								else if (schema.event_version() == 1)
								{
									RtlCopyMemory(ELS->EventName, "LoaderDomainModuleLoad_V1", sizeof("LoaderDomainModuleLoad_V1"));
									auto ModuleID = safe_parse<uint64_t>(parser, L"ModuleID");
									auto AssemblyID = safe_parse<uint64_t>(parser, L"AssemblyID");
									auto AppDomainID = safe_parse<uint64_t>(parser, L"AppDomainID");
									auto ModuleFlags = safe_parse<uint32_t>(parser, L"ModuleFlags");
									auto ModuleILPath = wchar_to_char(safe_parse<std::wstring>(parser, L"ModuleILPath").c_str());
									auto ModuleNativePath = wchar_to_char(safe_parse<std::wstring>(parser, L"ModuleNativePath").c_str());
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS->field.FieldCount = 7;
									std::string s0 = std::to_string(ModuleID);
									std::string s1 = std::to_string(AssemblyID);
									std::string s2 = std::to_string(AppDomainID);
									std::string s3 = std::to_string(ModuleFlags);
									std::string s6 = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "moduleid", sizeof("moduleid"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "assemblyid", sizeof("assemblyid"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "appdomainid", sizeof("appdomainid"));
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
									RtlCopyMemory(ELS->field.Fields[3].FieldName, "moduleflags", sizeof("moduleflags"));
									RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
									RtlCopyMemory(ELS->field.Fields[4].FieldName, "moduleilpath", sizeof("moduleilpath"));
									RtlCopyMemory(ELS->field.Fields[4].FieldValue, ModuleILPath.c_str(), ModuleILPath.length());
									RtlCopyMemory(ELS->field.Fields[5].FieldName, "modulenativepath", sizeof("modulenativepath"));
									RtlCopyMemory(ELS->field.Fields[5].FieldValue, ModuleNativePath.c_str(), ModuleNativePath.length());
									RtlCopyMemory(ELS->field.Fields[6].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									RtlCopyMemory(ELS->field.Fields[6].FieldValue, s6.c_str(), s6.length());
								}
								break;
							}
							case 152:
							case 153:
							{
								if (schema.event_version() == 0)
								{
									if (schema.event_id() == 152) RtlCopyMemory(ELS->EventName, "LoaderModuleLoad", sizeof("LoaderModuleLoad"));
									else RtlCopyMemory(ELS->EventName, "LoaderModuleUnload", sizeof("LoaderModuleUnload"));

									auto ModuleID = safe_parse<uint64_t>(parser, L"ModuleID");
									auto AssemblyID = safe_parse<uint64_t>(parser, L"AssemblyID");
									auto ModuleFlags = safe_parse<uint32_t>(parser, L"ModuleFlags");
									auto ModuleILPath = wchar_to_char(safe_parse<std::wstring>(parser, L"ModuleILPath").c_str());
									auto ModuleNativePath = wchar_to_char(safe_parse<std::wstring>(parser, L"ModuleNativePath").c_str());
									ELS->field.FieldCount = 5;
									std::string s0 = std::to_string(ModuleID);
									std::string s1 = std::to_string(AssemblyID);
									std::string s2 = std::to_string(ModuleFlags);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "moduleid", sizeof("moduleid"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "assemblyid", sizeof("assemblyid"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "moduleflags", sizeof("moduleflags"));
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
									RtlCopyMemory(ELS->field.Fields[3].FieldName, "moduleilpath", sizeof("moduleilpath"));
									RtlCopyMemory(ELS->field.Fields[3].FieldValue, ModuleILPath.c_str(), ModuleILPath.length());
									RtlCopyMemory(ELS->field.Fields[4].FieldName, "modulenativepath", sizeof("modulenativepath"));
									RtlCopyMemory(ELS->field.Fields[4].FieldValue, ModuleNativePath.c_str(), ModuleNativePath.length());
								}
								else if (schema.event_version() == 1 || schema.event_version() == 2)
								{
									if (schema.event_id() == 152)
									{
										if (schema.event_version() == 1) RtlCopyMemory(ELS->EventName, "LoaderModuleLoad_V1", sizeof("LoaderModuleLoad_V1"));
										else RtlCopyMemory(ELS->EventName, "LoaderModuleLoad_V2", sizeof("LoaderModuleLoad_V2"));
									}
									else
									{
										if (schema.event_version() == 1) RtlCopyMemory(ELS->EventName, "LoaderModuleUnload_V1", sizeof("LoaderModuleUnload_V1"));
										else RtlCopyMemory(ELS->EventName, "LoaderModuleUnload_V2", sizeof("LoaderModuleUnload_V2"));
									}

									auto ModuleID = safe_parse<uint64_t>(parser, L"ModuleID");
									auto AssemblyID = safe_parse<uint64_t>(parser, L"AssemblyID");
									auto ModuleFlags = safe_parse<uint32_t>(parser, L"ModuleFlags");
									auto ModuleILPath = wchar_to_char(safe_parse<std::wstring>(parser, L"ModuleILPath").c_str());
									auto ModuleNativePath = wchar_to_char(safe_parse<std::wstring>(parser, L"ModuleNativePath").c_str());
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS->field.FieldCount = 6;
									std::string s0 = std::to_string(ModuleID);
									std::string s1 = std::to_string(AssemblyID);
									std::string s2 = std::to_string(ModuleFlags);
									std::string s5 = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "moduleid", sizeof("moduleid"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "assemblyid", sizeof("assemblyid"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "moduleflags", sizeof("moduleflags"));
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
									RtlCopyMemory(ELS->field.Fields[3].FieldName, "moduleilpath", sizeof("moduleilpath"));
									RtlCopyMemory(ELS->field.Fields[3].FieldValue, ModuleILPath.c_str(), ModuleILPath.length());
									RtlCopyMemory(ELS->field.Fields[4].FieldName, "modulenativepath", sizeof("modulenativepath"));
									RtlCopyMemory(ELS->field.Fields[4].FieldValue, ModuleNativePath.c_str(), ModuleNativePath.length());
									RtlCopyMemory(ELS->field.Fields[5].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									RtlCopyMemory(ELS->field.Fields[5].FieldValue, s5.c_str(), s5.length());
								}
								break;
							}
							case 154:
							case 155:
							{
								if (schema.event_version() == 0)
								{
									if (schema.event_id() == 154) RtlCopyMemory(ELS->EventName, "LoaderAssemblyLoad", sizeof("LoaderAssemblyLoad"));
									else RtlCopyMemory(ELS->EventName, "LoaderAssemblyUnload", sizeof("LoaderAssemblyUnload"));

									auto AssemblyID = safe_parse<uint64_t>(parser, L"AssemblyID");
									auto AppDomainID = safe_parse<uint64_t>(parser, L"AppDomainID");
									auto AssemblyFlags = safe_parse<uint32_t>(parser, L"AssemblyFlags");
									auto FullyQualifiedAssemblyName = wchar_to_char(safe_parse<std::wstring>(parser, L"FullyQualifiedAssemblyName").c_str());
									ELS->field.FieldCount = 4;
									std::string s0 = std::to_string(AssemblyID);
									std::string s1 = std::to_string(AppDomainID);
									std::string s2 = std::to_string(AssemblyFlags);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "assemblyid", sizeof("assemblyid"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "appdomainid", sizeof("appdomainid"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "assemblyflags", sizeof("assemblyflags"));
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
									RtlCopyMemory(ELS->field.Fields[3].FieldName, "fullyqualifiedassemblyname", sizeof("fullyqualifiedassemblyname"));
									RtlCopyMemory(ELS->field.Fields[3].FieldValue, FullyQualifiedAssemblyName.c_str(), FullyQualifiedAssemblyName.length());
								}
								else if (schema.event_version() == 1)
								{
									if (schema.event_id() == 154) RtlCopyMemory(ELS->EventName, "LoaderAssemblyLoad_V1", sizeof("LoaderAssemblyLoad_V1"));
									else RtlCopyMemory(ELS->EventName, "LoaderAssemblyUnload_V1", sizeof("LoaderAssemblyUnload_V1"));

									auto AssemblyID = safe_parse<uint64_t>(parser, L"AssemblyID");
									auto AppDomainID = safe_parse<uint64_t>(parser, L"AppDomainID");
									auto BindingID = safe_parse<uint64_t>(parser, L"BindingID");
									auto AssemblyFlags = safe_parse<uint32_t>(parser, L"AssemblyFlags");
									auto FullyQualifiedAssemblyName = wchar_to_char(safe_parse<std::wstring>(parser, L"FullyQualifiedAssemblyName").c_str());
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS->field.FieldCount = 6;
									std::string s0 = std::to_string(AssemblyID);
									std::string s1 = std::to_string(AppDomainID);
									std::string s2 = std::to_string(AssemblyFlags);
									std::string s4 = std::to_string(BindingID);
									std::string s5 = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "assemblyid", sizeof("assemblyid"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "appdomainid", sizeof("appdomainid"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "assemblyflags", sizeof("assemblyflags"));
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
									RtlCopyMemory(ELS->field.Fields[3].FieldName, "fullyqualifiedassemblyname", sizeof("fullyqualifiedassemblyname"));
									RtlCopyMemory(ELS->field.Fields[3].FieldValue, FullyQualifiedAssemblyName.c_str(), FullyQualifiedAssemblyName.length());
									RtlCopyMemory(ELS->field.Fields[4].FieldName, "bindingid", sizeof("bindingid"));
									RtlCopyMemory(ELS->field.Fields[4].FieldValue, s4.c_str(), s4.length());
									RtlCopyMemory(ELS->field.Fields[5].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									RtlCopyMemory(ELS->field.Fields[5].FieldValue, s5.c_str(), s5.length());
								}
								break;
							}
							case 156:
							case 157:
							{
								if (schema.event_version() == 0)
								{
									if (schema.event_id() == 156) RtlCopyMemory(ELS->EventName, "LoaderAppDomainLoad", sizeof("LoaderAppDomainLoad"));
									else RtlCopyMemory(ELS->EventName, "LoaderAppDomainUnload", sizeof("LoaderAppDomainUnload"));

									auto AppDomainID = safe_parse<uint64_t>(parser, L"AppDomainID");
									auto AppDomainFlags = safe_parse<uint32_t>(parser, L"AppDomainFlags");
									auto AppDomainName = wchar_to_char(safe_parse<std::wstring>(parser, L"AppDomainName").c_str());
									ELS->field.FieldCount = 3;
									std::string s0 = std::to_string(AppDomainID);
									std::string s1 = std::to_string(AppDomainFlags);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "appdomainid", sizeof("appdomainid"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "appdomainflags", sizeof("appdomainflags"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "appdomainname", sizeof("appdomainname"));
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, AppDomainName.c_str(), AppDomainName.length());
								}
								else if (schema.event_version() == 1)
								{
									if (schema.event_id() == 156) RtlCopyMemory(ELS->EventName, "LoaderAppDomainLoad_V1", sizeof("LoaderAppDomainLoad_V1"));
									else RtlCopyMemory(ELS->EventName, "LoaderAppDomainUnload_V1", sizeof("LoaderAppDomainUnload_V1"));

									auto AppDomainID = safe_parse<uint64_t>(parser, L"AppDomainID");
									auto AppDomainFlags = safe_parse<uint32_t>(parser, L"AppDomainFlags");
									auto AppDomainName = wchar_to_char(safe_parse<std::wstring>(parser, L"AppDomainName").c_str());
									auto AppDomainIndex = safe_parse<uint32_t>(parser, L"AppDomainIndex");
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS->field.FieldCount = 5;
									std::string s0 = std::to_string(AppDomainID);
									std::string s1 = std::to_string(AppDomainFlags);
									std::string s3 = std::to_string(AppDomainIndex);
									std::string s4 = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "appdomainid", sizeof("appdomainid"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "appdomainflags", sizeof("appdomainflags"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "appdomainname", sizeof("appdomainname"));
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, AppDomainName.c_str(), AppDomainName.length());
									RtlCopyMemory(ELS->field.Fields[3].FieldName, "appdomainindex", sizeof("appdomainindex"));
									RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
									RtlCopyMemory(ELS->field.Fields[4].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									RtlCopyMemory(ELS->field.Fields[4].FieldValue, s4.c_str(), s4.length());
								}
								break;
							}
							case 158:
							{
								RtlCopyMemory(ELS->EventName, "ClrPerfTrackModuleRangeLoad", sizeof("ClrPerfTrackModuleRangeLoad"));
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								auto ModuleID = safe_parse<uint64_t>(parser, L"ModuleID");
								auto RangeBegin = safe_parse<uint32_t>(parser, L"RangeBegin");
								auto RangeSize = safe_parse<uint32_t>(parser, L"RangeSize");
								auto RangeType = safe_parse<uint8_t>(parser, L"RangeType");
								ELS->field.FieldCount = 5;
								std::string s0 = std::to_string(ClrInstanceID);
								std::string s1 = std::to_string(ModuleID);
								std::string s2 = std::to_string(RangeBegin);
								std::string s3 = std::to_string(RangeSize);
								std::string s4 = std::to_string(RangeType);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "moduleid", sizeof("moduleid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "rangebegin", sizeof("rangebegin"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS->field.Fields[3].FieldName, "rangesize", sizeof("rangesize"));
								RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
								RtlCopyMemory(ELS->field.Fields[4].FieldName, "rangetype", sizeof("rangetype"));
								RtlCopyMemory(ELS->field.Fields[4].FieldValue, s4.c_str(), s4.length());
								break;
							}
							case 181:
							case 182:
							{
								if (schema.event_version() == 0)
								{
									if (schema.event_id() == 181) RtlCopyMemory(ELS->EventName, "StrongNameVerificationStart", sizeof("StrongNameVerificationStart"));
									else RtlCopyMemory(ELS->EventName, "StrongNameVerificationStop", sizeof("StrongNameVerificationStop"));

									auto VerificationFlags = safe_parse<uint32_t>(parser, L"VerificationFlags");
									auto ErrorCode = safe_parse<uint32_t>(parser, L"ErrorCode");
									auto FullyQualifiedAssemblyName = wchar_to_char(safe_parse<std::wstring>(parser, L"FullyQualifiedAssemblyName").c_str());
									ELS->field.FieldCount = 3;
									std::string s0 = std::to_string(VerificationFlags);
									std::string s1 = std::to_string(ErrorCode);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "verificationflags", sizeof("verificationflags"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "errorcode", sizeof("errorcode"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "fullyqualifiedassemblyname", sizeof("fullyqualifiedassemblyname"));
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, FullyQualifiedAssemblyName.c_str(), FullyQualifiedAssemblyName.length());
								}
								else if (schema.event_version() == 1)
								{
									if (schema.event_id() == 181) RtlCopyMemory(ELS->EventName, "StrongNameVerificationStart_V1", sizeof("StrongNameVerificationStart_V1"));
									else RtlCopyMemory(ELS->EventName, "StrongNameVerificationStop_V1", sizeof("StrongNameVerificationStop_V1"));

									auto VerificationFlags = safe_parse<uint32_t>(parser, L"VerificationFlags");
									auto ErrorCode = safe_parse<uint32_t>(parser, L"ErrorCode");
									auto FullyQualifiedAssemblyName = wchar_to_char(safe_parse<std::wstring>(parser, L"FullyQualifiedAssemblyName").c_str());
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS->field.FieldCount = 4;
									std::string s0 = std::to_string(VerificationFlags);
									std::string s1 = std::to_string(ErrorCode);
									std::string s3 = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "verificationflags", sizeof("verificationflags"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "errorcode", sizeof("errorcode"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "fullyqualifiedassemblyname", sizeof("fullyqualifiedassemblyname"));
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, FullyQualifiedAssemblyName.c_str(), FullyQualifiedAssemblyName.length());
									RtlCopyMemory(ELS->field.Fields[3].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
								}
								break;
							}
							case 183:
							case 184:
							{
								if (schema.event_version() == 0)
								{
									if (schema.event_id() == 183) RtlCopyMemory(ELS->EventName, "AuthenticodeVerificationStart", sizeof("AuthenticodeVerificationStart"));
									else RtlCopyMemory(ELS->EventName, "AuthenticodeVerificationStop", sizeof("AuthenticodeVerificationStop"));

									auto VerificationFlags = safe_parse<uint32_t>(parser, L"VerificationFlags");
									auto ErrorCode = safe_parse<uint32_t>(parser, L"ErrorCode");
									auto ModulePath = wchar_to_char(safe_parse<std::wstring>(parser, L"ModulePath").c_str());
									ELS->field.FieldCount = 3;
									std::string s0 = std::to_string(VerificationFlags);
									std::string s1 = std::to_string(ErrorCode);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "verificationflags", sizeof("verificationflags"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "errorcode", sizeof("errorcode"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "modulepath", sizeof("modulepath"));
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, ModulePath.c_str(), ModulePath.length());
								}
								else if (schema.event_version() == 1)
								{
									if (schema.event_id() == 183) RtlCopyMemory(ELS->EventName, "AuthenticodeVerificationStart_V1", sizeof("AuthenticodeVerificationStart_V1"));
									else RtlCopyMemory(ELS->EventName, "AuthenticodeVerificationStop_V1", sizeof("AuthenticodeVerificationStop_V1"));

									auto VerificationFlags = safe_parse<uint32_t>(parser, L"VerificationFlags");
									auto ErrorCode = safe_parse<uint32_t>(parser, L"ErrorCode");
									auto ModulePath = wchar_to_char(safe_parse<std::wstring>(parser, L"ModulePath").c_str());
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS->field.FieldCount = 4;
									std::string s0 = std::to_string(VerificationFlags);
									std::string s1 = std::to_string(ErrorCode);
									std::string s3 = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS->field.Fields[0].FieldName, "verificationflags", sizeof("verificationflags"));
									RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS->field.Fields[1].FieldName, "errorcode", sizeof("errorcode"));
									RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
									RtlCopyMemory(ELS->field.Fields[2].FieldName, "modulepath", sizeof("modulepath"));
									RtlCopyMemory(ELS->field.Fields[2].FieldValue, ModulePath.c_str(), ModulePath.length());
									RtlCopyMemory(ELS->field.Fields[3].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
									RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
								}
								break;
							}
							case 187:
							{
								RtlCopyMemory(ELS->EventName, "RuntimeStart", sizeof("RuntimeStart"));
								field_idx = 0;
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								std::string s0 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s0.c_str(), s0.length());
								auto Sku = safe_parse<uint16_t>(parser, L"Sku");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "sku", sizeof("sku"));
								std::string s1 = std::to_string(Sku);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s1.c_str(), s1.length());
								auto BclMajorVersion = safe_parse<uint16_t>(parser, L"BclMajorVersion");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "bclmajorversion", sizeof("bclmajorversion"));
								std::string s2 = std::to_string(BclMajorVersion);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s2.c_str(), s2.length());
								auto BclMinorVersion = safe_parse<uint16_t>(parser, L"BclMinorVersion");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "bclminorversion", sizeof("bclminorversion"));
								std::string s3 = std::to_string(BclMinorVersion);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s3.c_str(), s3.length());
								auto BclBuildNumber = safe_parse<uint16_t>(parser, L"BclBuildNumber");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "bclbuildnumber", sizeof("bclbuildnumber"));
								std::string s4 = std::to_string(BclBuildNumber);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s4.c_str(), s4.length());
								auto BclQfeNumber = safe_parse<uint16_t>(parser, L"BclQfeNumber");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "bclqfenumber", sizeof("bclqfenumber"));
								std::string s5 = std::to_string(BclQfeNumber);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s5.c_str(), s5.length());
								auto VMMajorVersion = safe_parse<uint16_t>(parser, L"VMMajorVersion");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "vmmajorversion", sizeof("vmmajorversion"));
								std::string s6 = std::to_string(VMMajorVersion);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s6.c_str(), s6.length());
								auto VMMinorVersion = safe_parse<uint16_t>(parser, L"VMMinorVersion");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "vmminorversion", sizeof("vmminorversion"));
								std::string s7 = std::to_string(VMMinorVersion);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s7.c_str(), s7.length());
								auto VMBuildNumber = safe_parse<uint16_t>(parser, L"VMBuildNumber");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "vmbuildnumber", sizeof("vmbuildnumber"));
								std::string s8 = std::to_string(VMBuildNumber);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s8.c_str(), s8.length());
								auto VMQfeNumber = safe_parse<uint16_t>(parser, L"VMQfeNumber");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "vmqfenumber", sizeof("vmqfenumber"));
								std::string s9 = std::to_string(VMQfeNumber);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s9.c_str(), s9.length());
								auto StartupFlags = safe_parse<uint32_t>(parser, L"StartupFlags");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "startupflags", sizeof("startupflags"));
								std::string s10 = std::to_string(StartupFlags);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s10.c_str(), s10.length());
								auto StartupMode = safe_parse<uint8_t>(parser, L"StartupMode");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "startupmode", sizeof("startupmode"));
								std::string s11 = std::to_string(StartupMode);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s11.c_str(), s11.length());
								auto CommandLine = wchar_to_char(safe_parse<std::wstring>(parser, L"CommandLine").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "commandline", sizeof("commandline"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, CommandLine.c_str(), CommandLine.length());
								auto RuntimeDllPath = wchar_to_char(safe_parse<std::wstring>(parser, L"RuntimeDllPath").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "runtimedllpath", sizeof("runtimedllpath"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, RuntimeDllPath.c_str(), RuntimeDllPath.length());
								ELS->field.FieldCount = field_idx;
								break;
							}
							case 190:
							{
								RtlCopyMemory(ELS->EventName, "MethodMethodILToNativeMap", sizeof("MethodMethodILToNativeMap"));
								auto MethodID = safe_parse<uint64_t>(parser, L"MethodID");
								auto ReJITID = safe_parse<uint64_t>(parser, L"ReJITID");
								auto MethodExtent = safe_parse<uint8_t>(parser, L"MethodExtent");
								auto CountOfMapEntries = safe_parse<uint16_t>(parser, L"CountOfMapEntries");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 5;
								std::string s0 = std::to_string(MethodID);
								std::string s1 = std::to_string(ReJITID);
								std::string s2 = std::to_string(MethodExtent);
								std::string s3 = std::to_string(CountOfMapEntries);
								std::string s4 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "methodid", sizeof("methodid"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "rejitid", sizeof("rejitid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "methodextent", sizeof("methodextent"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS->field.Fields[3].FieldName, "countofmapentries", sizeof("countofmapentries"));
								RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
								RtlCopyMemory(ELS->field.Fields[4].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[4].FieldValue, s4.c_str(), s4.length());
								break;
							}
							case 200:
							{
								RtlCopyMemory(ELS->EventName, "GCIncreaseMemoryPressure", sizeof("GCIncreaseMemoryPressure"));
								auto BytesAllocated = safe_parse<uint64_t>(parser, L"BytesAllocated");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 2;
								std::string s0 = std::to_string(BytesAllocated);
								std::string s1 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "bytesallocated", sizeof("bytesallocated"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								break;
							}
							case 201:
							{
								RtlCopyMemory(ELS->EventName, "GCDecreaseMemoryPressure", sizeof("GCDecreaseMemoryPressure"));
								auto BytesFreed = safe_parse<uint64_t>(parser, L"BytesFreed");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 2;
								std::string s0 = std::to_string(BytesFreed);
								std::string s1 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "bytesfreed", sizeof("bytesfreed"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								break;
							}
							case 202:
							{
								RtlCopyMemory(ELS->EventName, "GCMark", sizeof("GCMark"));
								auto HeapNum = safe_parse<uint32_t>(parser, L"HeapNum");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								auto Type = safe_parse<uint32_t>(parser, L"Type");
								auto Bytes = safe_parse<uint64_t>(parser, L"Bytes");
								ELS->field.FieldCount = 4;
								std::string s0 = std::to_string(HeapNum);
								std::string s1 = std::to_string(ClrInstanceID);
								std::string s2 = std::to_string(Type);
								std::string s3 = std::to_string(Bytes);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "heapnum", sizeof("heapnum"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "type", sizeof("type"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS->field.Fields[3].FieldName, "bytes", sizeof("bytes"));
								RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
								break;
							}
							case 203:
							{
								RtlCopyMemory(ELS->EventName, "GCGCJoin_V2", sizeof("GCGCJoin_V2"));
								auto Heap = safe_parse<uint32_t>(parser, L"Heap");
								auto JoinTime = safe_parse<uint32_t>(parser, L"JoinTime");
								auto JoinType = safe_parse<uint32_t>(parser, L"JoinType");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								auto JoinID = safe_parse<uint32_t>(parser, L"JoinID");
								ELS->field.FieldCount = 5;
								std::string s0 = std::to_string(Heap);
								std::string s1 = std::to_string(JoinTime);
								std::string s2 = std::to_string(JoinType);
								std::string s3 = std::to_string(ClrInstanceID);
								std::string s4 = std::to_string(JoinID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "heap", sizeof("heap"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "jointime", sizeof("jointime"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "jointype", sizeof("jointype"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS->field.Fields[3].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
								RtlCopyMemory(ELS->field.Fields[4].FieldName, "joinid", sizeof("joinid"));
								RtlCopyMemory(ELS->field.Fields[4].FieldValue, s4.c_str(), s4.length());
								break;
							}
							case 204:
							{
								RtlCopyMemory(ELS->EventName, "GCPerHeapHistory_V3", sizeof("GCPerHeapHistory_V3"));
								field_idx = 0;
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								std::string s0 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s0.c_str(), s0.length());
								auto FreeListAllocated = safe_parse<uint64_t>(parser, L"FreeListAllocated");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "freelistallocated", sizeof("freelistallocated"));
								std::string s1 = std::to_string(FreeListAllocated);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s1.c_str(), s1.length());
								auto FreeListRejected = safe_parse<uint64_t>(parser, L"FreeListRejected");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "freelistrejected", sizeof("freelistrejected"));
								std::string s2 = std::to_string(FreeListRejected);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s2.c_str(), s2.length());
								auto EndOfSegAllocated = safe_parse<uint64_t>(parser, L"EndOfSegAllocated");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "endofsegallocated", sizeof("endofsegallocated"));
								std::string s3 = std::to_string(EndOfSegAllocated);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s3.c_str(), s3.length());
								auto CondemnedAllocated = safe_parse<uint64_t>(parser, L"CondemnedAllocated");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "condemnedallocated", sizeof("condemnedallocated"));
								std::string s4 = std::to_string(CondemnedAllocated);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s4.c_str(), s4.length());
								auto PinnedAllocated = safe_parse<uint64_t>(parser, L"PinnedAllocated");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "pinnedallocated", sizeof("pinnedallocated"));
								std::string s5 = std::to_string(PinnedAllocated);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s5.c_str(), s5.length());
								auto PinnedAllocatedAdvance = safe_parse<uint64_t>(parser, L"PinnedAllocatedAdvance");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "pinnedallocatedadvance", sizeof("pinnedallocatedadvance"));
								std::string s6 = std::to_string(PinnedAllocatedAdvance);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s6.c_str(), s6.length());
								auto RunningFreeListEfficiency = safe_parse<uint32_t>(parser, L"RunningFreeListEfficiency");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "runningfreelistefficiency", sizeof("runningfreelistefficiency"));
								std::string s7 = std::to_string(RunningFreeListEfficiency);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s7.c_str(), s7.length());
								auto CondemnReasons0 = safe_parse<uint32_t>(parser, L"CondemnReasons0");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "condemnreasons0", sizeof("condemnreasons0"));
								std::string s8 = std::to_string(CondemnReasons0);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s8.c_str(), s8.length());
								auto CondemnReasons1 = safe_parse<uint32_t>(parser, L"CondemnReasons1");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "condemnreasons1", sizeof("condemnreasons1"));
								std::string s9 = std::to_string(CondemnReasons1);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s9.c_str(), s9.length());
								auto CompactMechanisms = safe_parse<uint32_t>(parser, L"CompactMechanisms");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "compactmechanisms", sizeof("compactmechanisms"));
								std::string s10 = std::to_string(CompactMechanisms);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s10.c_str(), s10.length());
								auto ExpandMechanisms = safe_parse<uint32_t>(parser, L"ExpandMechanisms");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "expandmechanisms", sizeof("expandmechanisms"));
								std::string s11 = std::to_string(ExpandMechanisms);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s11.c_str(), s11.length());
								auto HeapIndex = safe_parse<uint32_t>(parser, L"HeapIndex");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "heapindex", sizeof("heapindex"));
								std::string s12 = std::to_string(HeapIndex);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s12.c_str(), s12.length());
								auto ExtraGen0Commit = safe_parse<uint64_t>(parser, L"ExtraGen0Commit");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "extragen0commit", sizeof("extragen0commit"));
								std::string s13 = std::to_string(ExtraGen0Commit);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s13.c_str(), s13.length());
								ELS->field.FieldCount = field_idx;
								break;
							}
							case 205:
							{
								RtlCopyMemory(ELS->EventName, "GCGlobalHeapHistory_V2", sizeof("GCGlobalHeapHistory_V2"));
								auto FinalYoungestDesired = safe_parse<uint64_t>(parser, L"FinalYoungestDesired");
								auto NumHeaps = safe_parse<int32_t>(parser, L"NumHeaps");
								auto CondemnedGeneration = safe_parse<uint32_t>(parser, L"CondemnedGeneration");
								auto Gen0ReductionCount = safe_parse<uint32_t>(parser, L"Gen0ReductionCount");
								auto Reason = safe_parse<uint32_t>(parser, L"Reason");
								auto GlobalMechanisms = safe_parse<uint32_t>(parser, L"GlobalMechanisms");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								auto PauseMode = safe_parse<uint32_t>(parser, L"PauseMode");
								auto MemoryPressure = safe_parse<uint32_t>(parser, L"MemoryPressure");
								ELS->field.FieldCount = 9;
								std::string s0 = std::to_string(FinalYoungestDesired);
								std::string s1 = std::to_string(NumHeaps);
								std::string s2 = std::to_string(CondemnedGeneration);
								std::string s3 = std::to_string(Gen0ReductionCount);
								std::string s4 = std::to_string(Reason);
								std::string s5 = std::to_string(GlobalMechanisms);
								std::string s6 = std::to_string(ClrInstanceID);
								std::string s7 = std::to_string(PauseMode);
								std::string s8 = std::to_string(MemoryPressure);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "finalyoungestdesired", sizeof("finalyoungestdesired"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "numheaps", sizeof("numheaps"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "condemnedgeneration", sizeof("condemnedgeneration"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS->field.Fields[3].FieldName, "gen0reductioncount", sizeof("gen0reductioncount"));
								RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
								RtlCopyMemory(ELS->field.Fields[4].FieldName, "reason", sizeof("reason"));
								RtlCopyMemory(ELS->field.Fields[4].FieldValue, s4.c_str(), s4.length());
								RtlCopyMemory(ELS->field.Fields[5].FieldName, "globalmechanisms", sizeof("globalmechanisms"));
								RtlCopyMemory(ELS->field.Fields[5].FieldValue, s5.c_str(), s5.length());
								RtlCopyMemory(ELS->field.Fields[6].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[6].FieldValue, s6.c_str(), s6.length());
								RtlCopyMemory(ELS->field.Fields[7].FieldName, "pausemode", sizeof("pausemode"));
								RtlCopyMemory(ELS->field.Fields[7].FieldValue, s7.c_str(), s7.length());
								RtlCopyMemory(ELS->field.Fields[8].FieldName, "memorypressure", sizeof("memorypressure"));
								RtlCopyMemory(ELS->field.Fields[8].FieldValue, s8.c_str(), s8.length());
								break;
							}
							case 206:
							{
								RtlCopyMemory(ELS->EventName, "GCGCLoaded", sizeof("GCGCLoaded"));
								auto GCName = wchar_to_char(safe_parse<std::wstring>(parser, L"GCName").c_str());
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 2;
								std::string s1 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "gcname", sizeof("gcname"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, GCName.c_str(), GCName.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								break;
							}
							case 250:
							{
								RtlCopyMemory(ELS->EventName, "ExceptionCatchStart", sizeof("ExceptionCatchStart"));
								auto EntryEIP = safe_parse<uint64_t>(parser, L"EntryEIP");
								auto MethodID = safe_parse<uint64_t>(parser, L"MethodID");
								auto MethodName = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodName").c_str());
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 4;
								std::string s0 = std::to_string(EntryEIP);
								std::string s1 = std::to_string(MethodID);
								std::string s3 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "entryeip", sizeof("entryeip"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "methodid", sizeof("methodid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "methodname", sizeof("methodname"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, MethodName.c_str(), MethodName.length());
								RtlCopyMemory(ELS->field.Fields[3].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
								break;
							}
							case 252:
							{
								RtlCopyMemory(ELS->EventName, "ExceptionFinallyStart", sizeof("ExceptionFinallyStart"));
								auto EntryEIP = safe_parse<uint64_t>(parser, L"EntryEIP");
								auto MethodID = safe_parse<uint64_t>(parser, L"MethodID");
								auto MethodName = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodName").c_str());
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 4;
								std::string s0 = std::to_string(EntryEIP);
								std::string s1 = std::to_string(MethodID);
								std::string s3 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "entryeip", sizeof("entryeip"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "methodid", sizeof("methodid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "methodname", sizeof("methodname"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, MethodName.c_str(), MethodName.length());
								RtlCopyMemory(ELS->field.Fields[3].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
								break;
							}
							case 254:
							{
								RtlCopyMemory(ELS->EventName, "ExceptionFilterStart", sizeof("ExceptionFilterStart"));
								auto EntryEIP = safe_parse<uint64_t>(parser, L"EntryEIP");
								auto MethodID = safe_parse<uint64_t>(parser, L"MethodID");
								auto MethodName = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodName").c_str());
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS->field.FieldCount = 4;
								std::string s0 = std::to_string(EntryEIP);
								std::string s1 = std::to_string(MethodID);
								std::string s3 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[0].FieldName, "entryeip", sizeof("entryeip"));
								RtlCopyMemory(ELS->field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS->field.Fields[1].FieldName, "methodid", sizeof("methodid"));
								RtlCopyMemory(ELS->field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS->field.Fields[2].FieldName, "methodname", sizeof("methodname"));
								RtlCopyMemory(ELS->field.Fields[2].FieldValue, MethodName.c_str(), MethodName.length());
								RtlCopyMemory(ELS->field.Fields[3].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								RtlCopyMemory(ELS->field.Fields[3].FieldValue, s3.c_str(), s3.length());
								break;
							}
							case 135:
							{
								RtlCopyMemory(ELS->EventName, "MethodDCStartCompleteV2", sizeof("MethodDCStartCompleteV2"));
								ELS->field.FieldCount = 0;
								break;
							}
							case 136:
							{
								RtlCopyMemory(ELS->EventName, "MethodDCEndCompleteV2", sizeof("MethodDCEndCompleteV2"));
								ELS->field.FieldCount = 0;
								break;
							}
							case 185:
							{
								RtlCopyMemory(ELS->EventName, "MethodInliningSucceeded", sizeof("MethodInliningSucceeded"));
								field_idx = 0;
								auto MethodBeingCompiledNamespace = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodBeingCompiledNamespace").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "methodbeingcompilednamespace", sizeof("methodbeingcompilednamespace"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, MethodBeingCompiledNamespace.c_str(), MethodBeingCompiledNamespace.length());

								auto MethodBeingCompiledName = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodBeingCompiledName").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "methodbeingcompiledname", sizeof("methodbeingcompiledname"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, MethodBeingCompiledName.c_str(), MethodBeingCompiledName.length());

								auto MethodBeingCompiledNameSignature = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodBeingCompiledNameSignature").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "methodbeingcompilednamesignature", sizeof("methodbeingcompilednamesignature"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, MethodBeingCompiledNameSignature.c_str(), MethodBeingCompiledNameSignature.length());

								auto InlinerNamespace = wchar_to_char(safe_parse<std::wstring>(parser, L"InlinerNamespace").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "inlinernamespace", sizeof("inlinernamespace"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, InlinerNamespace.c_str(), InlinerNamespace.length());

								auto InlinerName = wchar_to_char(safe_parse<std::wstring>(parser, L"InlinerName").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "inlinername", sizeof("inlinername"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, InlinerName.c_str(), InlinerName.length());

								auto InlinerNameSignature = wchar_to_char(safe_parse<std::wstring>(parser, L"InlinerNameSignature").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "inlinernamesignature", sizeof("inlinernamesignature"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, InlinerNameSignature.c_str(), InlinerNameSignature.length());

								auto InlineeNamespace = wchar_to_char(safe_parse<std::wstring>(parser, L"InlineeNamespace").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "inlineenamespace", sizeof("inlineenamespace"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, InlineeNamespace.c_str(), InlineeNamespace.length());

								auto InlineeName = wchar_to_char(safe_parse<std::wstring>(parser, L"InlineeName").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "inlineename", sizeof("inlineename"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, InlineeName.c_str(), InlineeName.length());

								auto InlineeNameSignature = wchar_to_char(safe_parse<std::wstring>(parser, L"InlineeNameSignature").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "inlineenamesignature", sizeof("inlineenamesignature"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, InlineeNameSignature.c_str(), InlineeNameSignature.length());

								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								std::string s9 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s9.c_str(), s9.length());

								ELS->field.FieldCount = field_idx;
								break;
							}
							case 186:
							{
								RtlCopyMemory(ELS->EventName, "MethodInliningFailed", sizeof("MethodInliningFailed"));
								field_idx = 0;
								auto MethodBeingCompiledNamespace = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodBeingCompiledNamespace").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "methodbeingcompilednamespace", sizeof("methodbeingcompilednamespace"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, MethodBeingCompiledNamespace.c_str(), MethodBeingCompiledNamespace.length());

								auto MethodBeingCompiledName = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodBeingCompiledName").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "methodbeingcompiledname", sizeof("methodbeingcompiledname"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, MethodBeingCompiledName.c_str(), MethodBeingCompiledName.length());

								auto MethodBeingCompiledNameSignature = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodBeingCompiledNameSignature").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "methodbeingcompilednamesignature", sizeof("methodbeingcompilednamesignature"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, MethodBeingCompiledNameSignature.c_str(), MethodBeingCompiledNameSignature.length());

								auto InlinerNamespace = wchar_to_char(safe_parse<std::wstring>(parser, L"InlinerNamespace").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "inlinernamespace", sizeof("inlinernamespace"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, InlinerNamespace.c_str(), InlinerNamespace.length());

								auto InlinerName = wchar_to_char(safe_parse<std::wstring>(parser, L"InlinerName").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "inlinername", sizeof("inlinername"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, InlinerName.c_str(), InlinerName.length());

								auto InlinerNameSignature = wchar_to_char(safe_parse<std::wstring>(parser, L"InlinerNameSignature").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "inlinernamesignature", sizeof("inlinernamesignature"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, InlinerNameSignature.c_str(), InlinerNameSignature.length());

								auto InlineeNamespace = wchar_to_char(safe_parse<std::wstring>(parser, L"InlineeNamespace").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "inlineenamespace", sizeof("inlineenamespace"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, InlineeNamespace.c_str(), InlineeNamespace.length());

								auto InlineeName = wchar_to_char(safe_parse<std::wstring>(parser, L"InlineeName").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "inlineename", sizeof("inlineename"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, InlineeName.c_str(), InlineeName.length());

								auto InlineeNameSignature = wchar_to_char(safe_parse<std::wstring>(parser, L"InlineeNameSignature").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "inlineenamesignature", sizeof("inlineenamesignature"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, InlineeNameSignature.c_str(), InlineeNameSignature.length());

								auto FailAlways = safe_parse<bool>(parser, L"FailAlways");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "failalways", sizeof("failalways"));
								std::string s9 = FailAlways ? "true" : "false";
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s9.c_str(), s9.length());

								auto FailReason = safe_parse<std::string>(parser, L"FailReason");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "failreason", sizeof("failreason"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, FailReason.c_str(), FailReason.length());

								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								std::string s11 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s11.c_str(), s11.length());

								ELS->field.FieldCount = field_idx;
								break;
							}
							case 188:
							{
								RtlCopyMemory(ELS->EventName, "MethodTailCallSucceeded", sizeof("MethodTailCallSucceeded"));
								field_idx = 0;
								auto MethodBeingCompiledNamespace = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodBeingCompiledNamespace").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "methodbeingcompilednamespace", sizeof("methodbeingcompilednamespace"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, MethodBeingCompiledNamespace.c_str(), MethodBeingCompiledNamespace.length());

								auto MethodBeingCompiledName = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodBeingCompiledName").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "methodbeingcompiledname", sizeof("methodbeingcompiledname"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, MethodBeingCompiledName.c_str(), MethodBeingCompiledName.length());

								auto MethodBeingCompiledNameSignature = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodBeingCompiledNameSignature").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "methodbeingcompilednamesignature", sizeof("methodbeingcompilednamesignature"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, MethodBeingCompiledNameSignature.c_str(), MethodBeingCompiledNameSignature.length());

								auto CallerNamespace = wchar_to_char(safe_parse<std::wstring>(parser, L"CallerNamespace").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "callernamespace", sizeof("callernamespace"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, CallerNamespace.c_str(), CallerNamespace.length());

								auto CallerName = wchar_to_char(safe_parse<std::wstring>(parser, L"CallerName").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "callername", sizeof("callername"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, CallerName.c_str(), CallerName.length());

								auto CallerNameSignature = wchar_to_char(safe_parse<std::wstring>(parser, L"CallerNameSignature").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "callernamesignature", sizeof("callernamesignature"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, CallerNameSignature.c_str(), CallerNameSignature.length());

								auto CalleeNamespace = wchar_to_char(safe_parse<std::wstring>(parser, L"CalleeNamespace").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "calleenamespace", sizeof("calleenamespace"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, CalleeNamespace.c_str(), CalleeNamespace.length());

								auto CalleeName = wchar_to_char(safe_parse<std::wstring>(parser, L"CalleeName").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "calleename", sizeof("calleename"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, CalleeName.c_str(), CalleeName.length());

								auto CalleeNameSignature = wchar_to_char(safe_parse<std::wstring>(parser, L"CalleeNameSignature").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "calleenamesignature", sizeof("calleenamesignature"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, CalleeNameSignature.c_str(), CalleeNameSignature.length());

								auto TailPrefix = safe_parse<bool>(parser, L"TailPrefix");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "tailprefix", sizeof("tailprefix"));
								std::string s9 = TailPrefix ? "true" : "false";
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s9.c_str(), s9.length());

								auto TailCallType = safe_parse<uint32_t>(parser, L"TailCallType");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "tailcalltype", sizeof("tailcalltype"));
								std::string s10 = std::to_string(TailCallType);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s10.c_str(), s10.length());

								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								std::string s11 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s11.c_str(), s11.length());

								ELS->field.FieldCount = field_idx;
								break;
							}
							case 189:
							{
								RtlCopyMemory(ELS->EventName, "MethodTailCallFailed", sizeof("MethodTailCallFailed"));
								field_idx = 0;
								auto MethodBeingCompiledNamespace = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodBeingCompiledNamespace").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "methodbeingcompilednamespace", sizeof("methodbeingcompilednamespace"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, MethodBeingCompiledNamespace.c_str(), MethodBeingCompiledNamespace.length());

								auto MethodBeingCompiledName = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodBeingCompiledName").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "methodbeingcompiledname", sizeof("methodbeingcompiledname"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, MethodBeingCompiledName.c_str(), MethodBeingCompiledName.length());

								auto MethodBeingCompiledNameSignature = wchar_to_char(safe_parse<std::wstring>(parser, L"MethodBeingCompiledNameSignature").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "methodbeingcompilednamesignature", sizeof("methodbeingcompilednamesignature"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, MethodBeingCompiledNameSignature.c_str(), MethodBeingCompiledNameSignature.length());

								auto CallerNamespace = wchar_to_char(safe_parse<std::wstring>(parser, L"CallerNamespace").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "callernamespace", sizeof("callernamespace"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, CallerNamespace.c_str(), CallerNamespace.length());

								auto CallerName = wchar_to_char(safe_parse<std::wstring>(parser, L"CallerName").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "callername", sizeof("callername"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, CallerName.c_str(), CallerName.length());

								auto CallerNameSignature = wchar_to_char(safe_parse<std::wstring>(parser, L"CallerNameSignature").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "callernamesignature", sizeof("callernamesignature"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, CallerNameSignature.c_str(), CallerNameSignature.length());

								auto CalleeNamespace = wchar_to_char(safe_parse<std::wstring>(parser, L"CalleeNamespace").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "calleenamespace", sizeof("calleenamespace"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, CalleeNamespace.c_str(), CalleeNamespace.length());

								auto CalleeName = wchar_to_char(safe_parse<std::wstring>(parser, L"CalleeName").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "calleename", sizeof("calleename"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, CalleeName.c_str(), CalleeName.length());

								auto CalleeNameSignature = wchar_to_char(safe_parse<std::wstring>(parser, L"CalleeNameSignature").c_str());
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "calleenamesignature", sizeof("calleenamesignature"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, CalleeNameSignature.c_str(), CalleeNameSignature.length());

								auto TailPrefix = safe_parse<bool>(parser, L"TailPrefix");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "tailprefix", sizeof("tailprefix"));
								std::string s9 = TailPrefix ? "true" : "false";
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s9.c_str(), s9.length());

								auto FailReason = safe_parse<std::string>(parser, L"FailReason");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "failreason", sizeof("failreason"));
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, FailReason.c_str(), FailReason.length());

								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								RtlCopyMemory(ELS->field.Fields[field_idx].FieldName, "clrinstanceid", sizeof("clrinstanceid"));
								std::string s11 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS->field.Fields[field_idx++].FieldValue, s11.c_str(), s11.length());

								ELS->field.FieldCount = field_idx;
								break;
							}
							case 240:
							{
								RtlCopyMemory(ELS->EventName, "DebugIPCEventStart", sizeof("DebugIPCEventStart"));
								ELS->field.FieldCount = 0;
								break;
							}
							case 241:
							{
								RtlCopyMemory(ELS->EventName, "DebugIPCEventStop", sizeof("DebugIPCEventStop"));
								ELS->field.FieldCount = 0;
								break;
							}
							case 242:
							{
								RtlCopyMemory(ELS->EventName, "DebugExceptionProcessingStart", sizeof("DebugExceptionProcessingStart"));
								ELS->field.FieldCount = 0;
								break;
							}
							case 243:
							{
								RtlCopyMemory(ELS->EventName, "DebugExceptionProcessingStop", sizeof("DebugExceptionProcessingStop"));
								ELS->field.FieldCount = 0;
								break;
							}
							case 251:
							{
								RtlCopyMemory(ELS->EventName, "ExceptionCatchStop", sizeof("ExceptionCatchStop"));
								ELS->field.FieldCount = 0;
								break;
							}
							case 253:
							{
								RtlCopyMemory(ELS->EventName, "ExceptionFinallyStop", sizeof("ExceptionFinallyStop"));
								ELS->field.FieldCount = 0;
								break;
							}
							case 255:
							{
								RtlCopyMemory(ELS->EventName, "ExceptionFilterStop", sizeof("ExceptionFilterStop"));
								ELS->field.FieldCount = 0;
								break;
							}
							case 256:
							{
								RtlCopyMemory(ELS->EventName, "ExceptionStop", sizeof("ExceptionStop"));
								ELS->field.FieldCount = 0;
								break;
							}
							default:
							{
								// 처리되지 않은 이벤트는 원래 코드처럼 schema에서 이벤트 이름을 가져옵니다.
								std::wstring eventNameW = schema.event_name();
								if (!eventNameW.empty())
								{
									std::string eventNameA = wchar_to_char(eventNameW.c_str());
									RtlCopyMemory(ELS->EventName, eventNameA.c_str(), eventNameA.length());
								}
								ELS->field.FieldCount = 0;
								break;
							}
							}

							EDR::LogReceiver::log_s logStruct;
							logStruct.LogDataType = EDR::EventLog::Enum::StructBased;
							logStruct.Type = EDR::EventLog::Enum::etw;
							logStruct.logData = (unsigned char*)ELS;
							logStruct.logSize = sizeof(EDR::EventLog::Struct::ETW::ETW_Log_Struct);

							this->Queue.putRaw(&logStruct);
						}
					);
				}
				~DotNetManager() {}

				bool AddProviderToTrace(krabs::user_trace& ETW_tracer)
				{
					try
					{
						ETW_tracer.enable(dotnet_provider);
						return true;
					}
					catch (const std::exception& e)
					{
						std::wcerr << L"Failed to enable .NET provider: " << e.what() << std::endl;
						return false;
					}
				}

				EDR::Util::Queue::IQueue& Queue;
			private:
				krabs::provider<> dotnet_provider;
				
			};

		}
	}

}


#endif
/*
--
``xml
<templates>
		  <template tid="GCStartArgs">
			<data name="Count" inType="win:UInt32" />
			<data name="Reason" inType="win:UInt32" map="GCReasonMap" />
		  </template>
		  <template tid="GCStopArgs">
			<data name="Count" inType="win:UInt32" />
			<data name="Depth" inType="win:UInt16" />
		  </template>
		  <template tid="GCHeapStatsArgs">
			<data name="GenerationSize0" inType="win:UInt64" />
			<data name="TotalPromotedSize0" inType="win:UInt64" />
			<data name="GenerationSize1" inType="win:UInt64" />
			<data name="TotalPromotedSize1" inType="win:UInt64" />
			<data name="GenerationSize2" inType="win:UInt64" />
			<data name="TotalPromotedSize2" inType="win:UInt64" />
			<data name="GenerationSize3" inType="win:UInt64" />
			<data name="TotalPromotedSize3" inType="win:UInt64" />
			<data name="FinalizationPromotedSize" inType="win:UInt64" />
			<data name="FinalizationPromotedCount" inType="win:UInt64" />
			<data name="PinnedObjectCount" inType="win:UInt32" />
			<data name="SinkBlockCount" inType="win:UInt32" />
			<data name="GCHandleCount" inType="win:UInt32" />
		  </template>
		  <template tid="GCCreateSegmentArgs">
			<data name="Address" inType="win:UInt64" />
			<data name="Size" inType="win:UInt64" />
			<data name="Type" inType="win:UInt32" map="GCSegmentTypeMap" />
		  </template>
		  <template tid="GCFreeSegmentArgs">
			<data name="Address" inType="win:UInt64" />
		  </template>
		  <template tid="GCSuspendEEStartArgs">
			<data name="Reason" inType="win:UInt16" />
		  </template>
		  <template tid="GCAllocationTickArgs">
			<data name="AllocationAmount" inType="win:UInt32" />
			<data name="AllocationKind" inType="win:UInt32" map="GCAllocationKindMap" />
		  </template>
		  <template tid="GCFinalizersStopArgs">
			<data name="Count" inType="win:UInt32" />
		  </template>
		  <template tid="TypeBulkTypeArgs">
			<data name="Count" inType="win:UInt32" />
			<data name="ClrInstanceID" inType="win:UInt16" />
			<data name="Values" inType="win:Int8" count="Count" />
		  </template>
		  <template tid="GCGCBulkRootEdgeArgs">
			<data name="Index" inType="win:UInt32" />
			<data name="Count" inType="win:UInt32" />
			<data name="ClrInstanceID" inType="win:UInt16" />
			<data name="Values" inType="win:UInt8" count="Count" />
		  </template>
		  <template tid="GCGCSampledObjectAllocationArgs">
			<data name="Address" inType="win:Pointer" />
			<data name="TypeID" inType="win:Pointer" />
			<data name="ObjectCountForTypeSample" inType="win:UInt32" />
			<data name="TotalSizeForTypeSample" inType="win:UInt64" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="GCGCGenerationRangeArgs">
			<data name="Generation" inType="win:UInt8" />
			<data name="RangeStart" inType="win:Pointer" />
			<data name="RangeUsedLength" inType="win:UInt64" />
			<data name="RangeReservedLength" inType="win:UInt64" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="GCMarkStackRootsArgs">
			<data name="HeapNum" inType="win:UInt32" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="GCFinalizeObjectArgs">
			<data name="TypeID" inType="win:Pointer" />
			<data name="ObjectID" inType="win:Pointer" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="GCSetGCHandleArgs">
			<data name="HandleID" inType="win:Pointer" />
			<data name="ObjectID" inType="win:Pointer" />
			<data name="Kind" inType="win:UInt32" />
			<data name="Generation" inType="win:UInt32" />
			<data name="AppDomainID" inType="win:UInt64" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="GCDestoryGCHandleArgs">
			<data name="HandleID" inType="win:Pointer" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="GCPinObjectAtGCTimeArgs">
			<data name="HandleID" inType="win:Pointer" />
			<data name="ObjectID" inType="win:Pointer" />
			<data name="ObjectSize" inType="win:UInt64" />
			<data name="TypeName" inType="win:UnicodeString" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="GCTriggeredArgs">
			<data name="Reason" inType="win:UInt32" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="GCGCBulkRootStaticVarArgs">
			<data name="Count" inType="win:UInt32" />
			<data name="AppDomainID" inType="win:UInt64" />
			<data name="ClrInstanceID" inType="win:UInt16" />
			<data name="Values" inType="win:UInt8" count="Count" />
		  </template>
		  <template tid="GCGCDynamicEventArgs">
			<data name="Name" inType="win:UnicodeString" />
			<data name="DataSize" inType="win:UInt32" />
			<data name="Data" inType="win:Binary" length="DataSize" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="WorkerThreadCreationV2StartArgs">
			<data name="WorkerThreadCount" inType="win:UInt32" />
			<data name="RetiredWorkerThreads" inType="win:UInt32" />
		  </template>
		  <template tid="IOThreadCreationStartArgs">
			<data name="IOThreadCount" inType="win:UInt32" />
			<data name="RetiredIOThreads" inType="win:UInt32" />
		  </template>
		  <template tid="ThreadpoolSuspensionV2StartArgs">
			<data name="ClrThreadID" inType="win:UInt32" />
			<data name="CpuUtilization" inType="win:UInt32" />
		  </template>
		  <template tid="ThreadPoolWorkerThreadStartArgs">
			<data name="ActiveWorkerThreadCount" inType="win:UInt32" />
			<data name="RetiredWorkerThreadCount" inType="win:UInt32" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="ThreadPoolWorkerThreadAdjustmentSampleArgs">
			<data name="Throughput" inType="win:Double" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="ThreadPoolWorkerThreadAdjustmentArgs">
			<data name="AverageThroughput" inType="win:Double" />
			<data name="NewWorkerThreadCount" inType="win:UInt32" />
			<data name="Reason" inType="win:UInt32" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="ThreadPoolWorkerThreadAdjustmentStatsArgs">
			<data name="Duration" inType="win:Double" />
			<data name="Throughput" inType="win:Double" />
			<data name="ThreadWave" inType="win:Double" />
			<data name="ThroughputWave" inType="win:Double" />
			<data name="ThroughputErrorEstimate" inType="win:Double" />
			<data name="AverageThroughputErrorEstimate" inType="win:Double" />
			<data name="ThroughputRatio" inType="win:Double" />
			<data name="Confidence" inType="win:Double" />
			<data name="NewControlSetting" inType="win:Double" />
			<data name="NewThreadWaveMagnitude" inType="win:UInt16" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="ThreadPoolWorkingThreadCountStartArgs">
			<data name="Count" inType="win:UInt32" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="ThreadPoolEnqueueArgs">
			<data name="WorkID" inType="win:Pointer" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="ThreadPoolIOEnqueueArgs">
			<data name="NativeOverlapped" inType="win:Pointer" />
			<data name="Overlapped" inType="win:Pointer" />
			<data name="MultiDequeues" inType="win:Boolean" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="ThreadPoolIODequeueArgs">
			<data name="NativeOverlapped" inType="win:Pointer" />
			<data name="Overlapped" inType="win:Pointer" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="ThreadCreatingArgs">
			<data name="ID" inType="win:Pointer" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="ClrStackWalkArgs">
			<data name="ClrInstanceID" inType="win:UInt16" />
			<data name="Reserved1" inType="win:UInt8" />
			<data name="Reserved2" inType="win:UInt8" />
			<data name="FrameCount" inType="win:UInt32" />
			<data name="Stack" inType="win:Pointer" />
		  </template>
		  <template tid="AppDomainResourceManagementMemAllocatedArgs">
			<data name="AppDomainID" inType="win:UInt64" />
			<data name="Allocated" inType="win:UInt64" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="AppDomainResourceManagementMemSurvivedArgs">
			<data name="AppDomainID" inType="win:UInt64" />
			<data name="Survived" inType="win:UInt64" />
			<data name="ProcessSurvived" inType="win:UInt64" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="AppDomainResourceManagementThreadCreatedArgs">
			<data name="ManagedThreadID" inType="win:UInt64" />
			<data name="AppDomainID" inType="win:UInt64" />
			<data name="Flags" inType="win:UInt32" map="ThreadFlagsMap" />
			<data name="ManagedThreadIndex" inType="win:UInt32" />
			<data name="OSThreadID" inType="win:UInt32" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="AppDomainResourceManagementThreadTerminatedArgs">
			<data name="ManagedThreadID" inType="win:UInt64" />
			<data name="AppDomainID" inType="win:UInt64" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="ILStubStubGeneratedArgs">
			<data name="ClrInstanceID" inType="win:UInt16" />
			<data name="ModuleID" inType="win:UInt64" />
			<data name="StubMethodID" inType="win:UInt64" />
			<data name="StubFlags" inType="win:UInt32" />
			<data name="ManagedInteropMethodToken" inType="win:UInt32" />
			<data name="ManagedInteropMethodNamespace" inType="win:UnicodeString" />
			<data name="ManagedInteropMethodName" inType="win:UnicodeString" />
			<data name="ManagedInteropMethodSignature" inType="win:UnicodeString" />
			<data name="NativeMethodSignature" inType="win:UnicodeString" />
			<data name="StubMethodSignature" inType="win:UnicodeString" />
			<data name="StubMethodILCode" inType="win:UnicodeString" />
		  </template>
		  <template tid="ILStubStubCacheHitArgs">
			<data name="ClrInstanceID" inType="win:UInt16" />
			<data name="ModuleID" inType="win:UInt64" />
			<data name="StubMethodID" inType="win:UInt64" />
			<data name="ManagedInteropMethodToken" inType="win:UInt32" />
			<data name="ManagedInteropMethodNamespace" inType="win:UnicodeString" />
			<data name="ManagedInteropMethodName" inType="win:UnicodeString" />
			<data name="ManagedInteropMethodSignature" inType="win:UnicodeString" />
		  </template>
		  <template tid="ContentionStopArgs">
			<data name="ContentionFlags" inType="win:UInt8" map="ContentionFlagsMap" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="MethodDCStartV2Args">
			<data name="MethodID" inType="win:UInt64" />
			<data name="ModuleID" inType="win:UInt64" />
			<data name="MethodStartAddress" inType="win:UInt64" />
			<data name="MethodSize" inType="win:UInt32" />
			<data name="MethodToken" inType="win:UInt32" />
			<data name="MethodFlags" inType="win:UInt32" />
		  </template>
		  <template tid="MethodDCStopV2Args">
			<data name="MethodID" inType="win:UInt64" />
			<data name="ModuleID" inType="win:UInt64" />
			<data name="MethodStartAddress" inType="win:UInt64" />
			<data name="MethodSize" inType="win:UInt32" />
			<data name="MethodToken" inType="win:UInt32" />
			<data name="MethodFlags" inType="win:UInt32" map="MethodFlagsMap" />
		  </template>
		  <template tid="MethodDCStartVerboseV2Args">
			<data name="MethodID" inType="win:UInt64" />
			<data name="ModuleID" inType="win:UInt64" />
			<data name="MethodStartAddress" inType="win:UInt64" />
			<data name="MethodSize" inType="win:UInt32" />
			<data name="MethodToken" inType="win:UInt32" />
			<data name="MethodFlags" inType="win:UInt32" />
			<data name="MethodNamespace" inType="win:UnicodeString" />
			<data name="MethodName" inType="win:UnicodeString" />
			<data name="MethodSignature" inType="win:UnicodeString" />
		  </template>
		  <template tid="MethodJittingStartedArgs">
			<data name="MethodID" inType="win:UInt64" />
			<data name="ModuleID" inType="win:UInt64" />
			<data name="MethodToken" inType="win:UInt32" />
			<data name="MethodILSize" inType="win:UInt32" />
			<data name="MethodNamespace" inType="win:UnicodeString" />
			<data name="MethodName" inType="win:UnicodeString" />
			<data name="MethodSignature" inType="win:UnicodeString" />
		  </template>
		  <template tid="LoaderModuleDCStartV2Args">
			<data name="ModuleID" inType="win:UInt64" />
			<data name="AssemblyID" inType="win:UInt64" />
			<data name="ModuleFlags" inType="win:UInt32" map="ModuleFlagsMap" />
			<data name="Reserved1" inType="win:UInt32" />
			<data name="ModuleILPath" inType="win:UnicodeString" />
			<data name="ModuleNativePath" inType="win:UnicodeString" />
		  </template>
		  <template tid="LoaderModuleDCStopV2Args">
			<data name="ModuleID" inType="win:UInt64" />
			<data name="AssemblyID" inType="win:UInt64" />
			<data name="ModuleFlags" inType="win:UInt32" />
			<data name="Reserved1" inType="win:UInt32" />
			<data name="ModuleILPath" inType="win:UnicodeString" />
			<data name="ModuleNativePath" inType="win:UnicodeString" />
		  </template>
		  <template tid="LoaderDomainModuleLoadArgs">
			<data name="ModuleID" inType="win:UInt64" />
			<data name="AssemblyID" inType="win:UInt64" />
			<data name="AppDomainID" inType="win:UInt64" />
			<data name="ModuleFlags" inType="win:UInt32" />
			<data name="Reserved1" inType="win:UInt32" />
			<data name="ModuleILPath" inType="win:UnicodeString" />
			<data name="ModuleNativePath" inType="win:UnicodeString" />
		  </template>
		  <template tid="LoaderAssemblyLoadArgs">
			<data name="AssemblyID" inType="win:UInt64" />
			<data name="AppDomainID" inType="win:UInt64" />
			<data name="AssemblyFlags" inType="win:UInt32" />
			<data name="FullyQualifiedAssemblyName" inType="win:UnicodeString" />
		  </template>
		  <template tid="LoaderAssemblyUnloadArgs">
			<data name="AssemblyID" inType="win:UInt64" />
			<data name="AppDomainID" inType="win:UInt64" />
			<data name="AssemblyFlags" inType="win:UInt32" map="AssemblyFlagsMap" />
			<data name="FullyQualifiedAssemblyName" inType="win:UnicodeString" />
		  </template>
		  <template tid="LoaderAppDomainLoadArgs">
			<data name="AppDomainID" inType="win:UInt64" />
			<data name="AppDomainFlags" inType="win:UInt32" map="AppDomainFlagsMap" />
			<data name="AppDomainName" inType="win:UnicodeString" />
		  </template>
		  <template tid="LoaderAppDomainUnloadArgs">
			<data name="AppDomainID" inType="win:UInt64" />
			<data name="AppDomainFlags" inType="win:UInt32" />
			<data name="AppDomainName" inType="win:UnicodeString" />
		  </template>
		  <template tid="ClrPerfTrackModuleRangeLoadArgs">
			<data name="ClrInstanceID" inType="win:UInt16" />
			<data name="ModuleID" inType="win:UInt64" />
			<data name="RangeBegin" inType="win:UInt32" />
			<data name="RangeSize" inType="win:UInt32" />
			<data name="RangeType" inType="win:UInt8" map="ModuleRangeTypeMap" />
		  </template>
		  <template tid="StrongNameVerificationStartArgs">
			<data name="VerificationFlags" inType="win:UInt32" />
			<data name="ErrorCode" inType="win:UInt32" />
			<data name="FullyQualifiedAssemblyName" inType="win:UnicodeString" />
		  </template>
		  <template tid="AuthenticodeVerificationStartArgs">
			<data name="VerificationFlags" inType="win:UInt32" />
			<data name="ErrorCode" inType="win:UInt32" />
			<data name="ModulePath" inType="win:UnicodeString" />
		  </template>
		  <template tid="MethodInliningSucceededArgs">
			<data name="MethodBeingCompiledNamespace" inType="win:UnicodeString" />
			<data name="MethodBeingCompiledName" inType="win:UnicodeString" />
			<data name="MethodBeingCompiledNameSignature" inType="win:UnicodeString" />
			<data name="InlinerNamespace" inType="win:UnicodeString" />
			<data name="InlinerName" inType="win:UnicodeString" />
			<data name="InlinerNameSignature" inType="win:UnicodeString" />
			<data name="InlineeNamespace" inType="win:UnicodeString" />
			<data name="InlineeName" inType="win:UnicodeString" />
			<data name="InlineeNameSignature" inType="win:UnicodeString" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="MethodInliningFailedArgs">
			<data name="MethodBeingCompiledNamespace" inType="win:UnicodeString" />
			<data name="MethodBeingCompiledName" inType="win:UnicodeString" />
			<data name="MethodBeingCompiledNameSignature" inType="win:UnicodeString" />
			<data name="InlinerNamespace" inType="win:UnicodeString" />
			<data name="InlinerName" inType="win:UnicodeString" />
			<data name="InlinerNameSignature" inType="win:UnicodeString" />
			<data name="InlineeNamespace" inType="win:UnicodeString" />
			<data name="InlineeName" inType="win:UnicodeString" />
			<data name="InlineeNameSignature" inType="win:UnicodeString" />
			<data name="FailAlways" inType="win:Boolean" />
			<data name="FailReason" inType="win:AnsiString" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="RuntimeStartArgs">
			<data name="ClrInstanceID" inType="win:UInt16" />
			<data name="Sku" inType="win:UInt16" />
			<data name="BclMajorVersion" inType="win:UInt16" />
			<data name="BclMinorVersion" inType="win:UInt16" />
			<data name="BclBuildNumber" inType="win:UInt16" />
			<data name="BclQfeNumber" inType="win:UInt16" />
			<data name="VMMajorVersion" inType="win:UInt16" />
			<data name="VMMinorVersion" inType="win:UInt16" />
			<data name="VMBuildNumber" inType="win:UInt16" />
			<data name="VMQfeNumber" inType="win:UInt16" />
			<data name="StartupFlags" inType="win:UInt32" />
			<data name="StartupMode" inType="win:UInt8" map="StartupModeMap" />
			<data name="CommandLine" inType="win:UnicodeString" />
			<data name="ComObjectGuid" inType="win:GUID" />
			<data name="RuntimeDllPath" inType="win:UnicodeString" />
		  </template>
		  <template tid="MethodTailCallSucceededArgs">
			<data name="MethodBeingCompiledNamespace" inType="win:UnicodeString" />
			<data name="MethodBeingCompiledName" inType="win:UnicodeString" />
			<data name="MethodBeingCompiledNameSignature" inType="win:UnicodeString" />
			<data name="CallerNamespace" inType="win:UnicodeString" />
			<data name="CallerName" inType="win:UnicodeString" />
			<data name="CallerNameSignature" inType="win:UnicodeString" />
			<data name="CalleeNamespace" inType="win:UnicodeString" />
			<data name="CalleeName" inType="win:UnicodeString" />
			<data name="CalleeNameSignature" inType="win:UnicodeString" />
			<data name="TailPrefix" inType="win:Boolean" />
			<data name="TailCallType" inType="win:UInt32" map="TailCallTypeMap" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="MethodTailCallFailedArgs">
			<data name="MethodBeingCompiledNamespace" inType="win:UnicodeString" />
			<data name="MethodBeingCompiledName" inType="win:UnicodeString" />
			<data name="MethodBeingCompiledNameSignature" inType="win:UnicodeString" />
			<data name="CallerNamespace" inType="win:UnicodeString" />
			<data name="CallerName" inType="win:UnicodeString" />
			<data name="CallerNameSignature" inType="win:UnicodeString" />
			<data name="CalleeNamespace" inType="win:UnicodeString" />
			<data name="CalleeName" inType="win:UnicodeString" />
			<data name="CalleeNameSignature" inType="win:UnicodeString" />
			<data name="TailPrefix" inType="win:Boolean" />
			<data name="FailReason" inType="win:AnsiString" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="MethodMethodILToNativeMapArgs">
			<data name="MethodID" inType="win:UInt64" />
			<data name="ReJITID" inType="win:UInt64" />
			<data name="MethodExtent" inType="win:UInt8" />
			<data name="CountOfMapEntries" inType="win:UInt16" />
			<data name="ILOffsets" inType="win:UInt32" count="CountOfMapEntries" />
			<data name="NativeOffsets" inType="win:UInt32" count="CountOfMapEntries" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="GCIncreaseMemoryPressureArgs">
			<data name="BytesAllocated" inType="win:UInt64" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="GCDecreaseMemoryPressureArgs">
			<data name="BytesFreed" inType="win:UInt64" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="GCMarkArgs">
			<data name="HeapNum" inType="win:UInt32" />
			<data name="ClrInstanceID" inType="win:UInt16" />
			<data name="Type" inType="win:UInt32" />
			<data name="Bytes" inType="win:UInt64" />
		  </template>
		  <template tid="GCGCLoadedArgs">
			<data name="GCName" inType="win:UnicodeString" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="ExceptionCatchStartArgs">
			<data name="EntryEIP" inType="win:UInt64" />
			<data name="MethodID" inType="win:UInt64" />
			<data name="MethodName" inType="win:UnicodeString" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="GCStartArgs_V1">
			<data name="Count" inType="win:UInt32" />
			<data name="Depth" inType="win:UInt32" />
			<data name="Reason" inType="win:UInt32" />
			<data name="Type" inType="win:UInt32" map="GCTypeMap" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="GCStopArgs_V1">
			<data name="Count" inType="win:UInt32" />
			<data name="Depth" inType="win:UInt32" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="GCRestartEEStopArgs_V1">
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="GCHeapStatsArgs_V1">
			<data name="GenerationSize0" inType="win:UInt64" />
			<data name="TotalPromotedSize0" inType="win:UInt64" />
			<data name="GenerationSize1" inType="win:UInt64" />
			<data name="TotalPromotedSize1" inType="win:UInt64" />
			<data name="GenerationSize2" inType="win:UInt64" />
			<data name="TotalPromotedSize2" inType="win:UInt64" />
			<data name="GenerationSize3" inType="win:UInt64" />
			<data name="TotalPromotedSize3" inType="win:UInt64" />
			<data name="FinalizationPromotedSize" inType="win:UInt64" />
			<data name="FinalizationPromotedCount" inType="win:UInt64" />
			<data name="PinnedObjectCount" inType="win:UInt32" />
			<data name="SinkBlockCount" inType="win:UInt32" />
			<data name="GCHandleCount" inType="win:UInt32" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="GCCreateSegmentArgs_V1">
			<data name="Address" inType="win:UInt64" />
			<data name="Size" inType="win:UInt64" />
			<data name="Type" inType="win:UInt32" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="GCFreeSegmentArgs_V1">
			<data name="Address" inType="win:UInt64" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="GCSuspendEEStartArgs_V1">
			<data name="Reason" inType="win:UInt32" />
			<data name="Count" inType="win:UInt32" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="GCAllocationTickArgs_V1">
			<data name="AllocationAmount" inType="win:UInt32" />
			<data name="AllocationKind" inType="win:UInt32" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="IOThreadCreationStartArgs_V1">
			<data name="IOThreadCount" inType="win:UInt32" />
			<data name="RetiredIOThreads" inType="win:UInt32" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="ExceptionStartArgs_V1">
			<data name="ExceptionType" inType="win:UnicodeString" />
			<data name="ExceptionMessage" inType="win:UnicodeString" />
			<data name="ExceptionEIP" inType="win:Pointer" />
			<data name="ExceptionHRESULT" inType="win:UInt32" />
			<data name="ExceptionFlags" inType="win:UInt16" map="ExceptionThrownFlagsMap" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="ContentionStartArgs_V1">
			<data name="ContentionFlags" inType="win:UInt8" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="MethodLoadArgs_V1">
			<data name="MethodID" inType="win:UInt64" />
			<data name="ModuleID" inType="win:UInt64" />
			<data name="MethodStartAddress" inType="win:UInt64" />
			<data name="MethodSize" inType="win:UInt32" />
			<data name="MethodToken" inType="win:UInt32" />
			<data name="MethodFlags" inType="win:UInt32" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="MethodLoadVerboseArgs_V1">
			<data name="MethodID" inType="win:UInt64" />
			<data name="ModuleID" inType="win:UInt64" />
			<data name="MethodStartAddress" inType="win:UInt64" />
			<data name="MethodSize" inType="win:UInt32" />
			<data name="MethodToken" inType="win:UInt32" />
			<data name="MethodFlags" inType="win:UInt32" />
			<data name="MethodNamespace" inType="win:UnicodeString" />
			<data name="MethodName" inType="win:UnicodeString" />
			<data name="MethodSignature" inType="win:UnicodeString" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="MethodJittingStartedArgs_V1">
			<data name="MethodID" inType="win:UInt64" />
			<data name="ModuleID" inType="win:UInt64" />
			<data name="MethodToken" inType="win:UInt32" />
			<data name="MethodILSize" inType="win:UInt32" />
			<data name="MethodNamespace" inType="win:UnicodeString" />
			<data name="MethodName" inType="win:UnicodeString" />
			<data name="MethodSignature" inType="win:UnicodeString" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="LoaderDomainModuleLoadArgs_V1">
			<data name="ModuleID" inType="win:UInt64" />
			<data name="AssemblyID" inType="win:UInt64" />
			<data name="AppDomainID" inType="win:UInt64" />
			<data name="ModuleFlags" inType="win:UInt32" />
			<data name="Reserved1" inType="win:UInt32" />
			<data name="ModuleILPath" inType="win:UnicodeString" />
			<data name="ModuleNativePath" inType="win:UnicodeString" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="LoaderModuleLoadArgs_V1">
			<data name="ModuleID" inType="win:UInt64" />
			<data name="AssemblyID" inType="win:UInt64" />
			<data name="ModuleFlags" inType="win:UInt32" />
			<data name="Reserved1" inType="win:UInt32" />
			<data name="ModuleILPath" inType="win:UnicodeString" />
			<data name="ModuleNativePath" inType="win:UnicodeString" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="LoaderAssemblyLoadArgs_V1">
			<data name="AssemblyID" inType="win:UInt64" />
			<data name="AppDomainID" inType="win:UInt64" />
			<data name="BindingID" inType="win:UInt64" />
			<data name="AssemblyFlags" inType="win:UInt32" />
			<data name="FullyQualifiedAssemblyName" inType="win:UnicodeString" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="LoaderAppDomainLoadArgs_V1">
			<data name="AppDomainID" inType="win:UInt64" />
			<data name="AppDomainFlags" inType="win:UInt32" />
			<data name="AppDomainName" inType="win:UnicodeString" />
			<data name="AppDomainIndex" inType="win:UInt32" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="StrongNameVerificationStartArgs_V1">
			<data name="VerificationFlags" inType="win:UInt32" />
			<data name="ErrorCode" inType="win:UInt32" />
			<data name="FullyQualifiedAssemblyName" inType="win:UnicodeString" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="AuthenticodeVerificationStartArgs_V1">
			<data name="VerificationFlags" inType="win:UInt32" />
			<data name="ErrorCode" inType="win:UInt32" />
			<data name="ModulePath" inType="win:UnicodeString" />
			<data name="ClrInstanceID" inType="win:UInt16" />
		  </template>
		  <template tid="GCStartArgs_V2">
			<data name="Count" inType="win:UInt32" />
			<data name="Depth" inType="win:UInt32" />
			<data name="Reason" inType="win:UInt32" />
			<data name="Type" inType="win:UInt32" />
			<data name="ClrInstanceID" inType="win:UInt16" />
			<data name="ClientSequenceNumber" inType="win:UInt64" />
		  </template>
		  <template tid="GCAllocationTickArgs_V2">
			<data name="AllocationAmount" inType="win:UInt32" />
			<data name="AllocationKind" inType="win:UInt32" />
			<data name="ClrInstanceID" inType="win:UInt16" />
			<data name="AllocationAmount64" inType="win:UInt64" />
			<data name="TypeID" inType="win:Pointer" />
			<data name="TypeName" inType="win:UnicodeString" />
			<data name="HeapIndex" inType="win:UInt32" />
		  </template>
		  <template tid="MethodLoadArgs_V2">
			<data name="MethodID" inType="win:UInt64" />
			<data name="ModuleID" inType="win:UInt64" />
			<data name="MethodStartAddress" inType="win:UInt64" />
			<data name="MethodSize" inType="win:UInt32" />
			<data name="MethodToken" inType="win:UInt32" />
			<data name="MethodFlags" inType="win:UInt32" />
			<data name="ClrInstanceID" inType="win:UInt16" />
			<data name="ReJITID" inType="win:UInt64" />
		  </template>
		  <template tid="MethodLoadVerboseArgs_V2">
			<data name="MethodID" inType="win:UInt64" />
			<data name="ModuleID" inType="win:UInt64" />
			<data name="MethodStartAddress" inType="win:UInt64" />
			<data name="MethodSize" inType="win:UInt32" />
			<data name="MethodToken" inType="win:UInt32" />
			<data name="MethodFlags" inType="win:UInt32" />
			<data name="MethodNamespace" inType="win:UnicodeString" />
			<data name="MethodName" inType="win:UnicodeString" />
			<data name="MethodSignature" inType="win:UnicodeString" />
			<data name="ClrInstanceID" inType="win:UInt16" />
			<data name="ReJITID" inType="win:UInt64" />
		  </template>
		  <template tid="LoaderModuleLoadArgs_V2">
			<data name="ModuleID" inType="win:UInt64" />
			<data name="AssemblyID" inType="win:UInt64" />
			<data name="ModuleFlags" inType="win:UInt32" />
			<data name="Reserved1" inType="win:UInt32" />
			<data name="ModuleILPath" inType="win:UnicodeString" />
			<data name="ModuleNativePath" inType="win:UnicodeString" />
			<data name="ClrInstanceID" inType="win:UInt16" />
			<data name="ManagedPdbSignature" inType="win:GUID" />
			<data name="ManagedPdbAge" inType="win:UInt32" />
			<data name="ManagedPdbBuildPath" inType="win:UnicodeString" />
			<data name="NativePdbSignature" inType="win:GUID" />
			<data name="NativePdbAge" inType="win:UInt32" />
			<data name="NativePdbBuildPath" inType="win:UnicodeString" />
		  </template>
		  <template tid="GCGCJoinArgs_V2">
			<data name="Heap" inType="win:UInt32" />
			<data name="JoinTime" inType="win:UInt32" />
			<data name="JoinType" inType="win:UInt32" />
			<data name="ClrInstanceID" inType="win:UInt16" />
			<data name="JoinID" inType="win:UInt32" />
		  </template>
		  <template tid="GCGlobalHeapHistoryArgs_V2">
			<data name="FinalYoungestDesired" inType="win:UInt64" />
			<data name="NumHeaps" inType="win:Int32" />
			<data name="CondemnedGeneration" inType="win:UInt32" />
			<data name="Gen0ReductionCount" inType="win:UInt32" />
			<data name="Reason" inType="win:UInt32" />
			<data name="GlobalMechanisms" inType="win:UInt32" />
			<data name="ClrInstanceID" inType="win:UInt16" />
			<data name="PauseMode" inType="win:UInt32" />
			<data name="MemoryPressure" inType="win:UInt32" />
		  </template>
		  <template tid="GCAllocationTickArgs_V3">
			<data name="AllocationAmount" inType="win:UInt32" />
			<data name="AllocationKind" inType="win:UInt32" />
			<data name="ClrInstanceID" inType="win:UInt16" />
			<data name="AllocationAmount64" inType="win:UInt64" />
			<data name="TypeID" inType="win:Pointer" />
			<data name="TypeName" inType="win:UnicodeString" />
			<data name="HeapIndex" inType="win:UInt32" />
			<data name="Address" inType="win:Pointer" />
		  </template>
		  <template tid="GCPerHeapHistoryArgs_V3">
			<data name="ClrInstanceID" inType="win:UInt16" />
			<data name="FreeListAllocated" inType="win:Pointer" />
			<data name="FreeListRejected" inType="win:Pointer" />
			<data name="EndOfSegAllocated" inType="win:Pointer" />
			<data name="CondemnedAllocated" inType="win:Pointer" />
			<data name="PinnedAllocated" inType="win:Pointer" />
			<data name="PinnedAllocatedAdvance" inType="win:Pointer" />
			<data name="RunningFreeListEfficiency" inType="win:UInt32" />
			<data name="CondemnReasons0" inType="win:UInt32" />
			<data name="CondemnReasons1" inType="win:UInt32" />
			<data name="CompactMechanisms" inType="win:UInt32" />
			<data name="ExpandMechanisms" inType="win:UInt32" />
			<data name="HeapIndex" inType="win:UInt32" />
			<data name="ExtraGen0Commit" inType="win:Pointer" />
			<data name="Count" inType="win:UInt32" />
			<data name="Values" inType="win:Pointer" count="Count" />
		  </template>
		</templates>
# -> EventName에 매핑된 속성데이터
```
```xml
<events>
		  <event value="1" symbol="GCStart" version="0" task="GC" opcode="win:Start" level="win:Informational" keywords="GCKeyword" template="GCStartArgs" />
		  <event value="1" symbol="GCStart_V1" version="1" task="GC" opcode="win:Start" level="win:Informational" keywords="GCKeyword" template="GCStartArgs_V1" />
		  <event value="1" symbol="GCStart_V2" version="2" task="GC" opcode="win:Start" level="win:Informational" keywords="GCKeyword" template="GCStartArgs_V2" />
		  <event value="2" symbol="GCStop" version="0" task="GC" opcode="win:Stop" level="win:Informational" keywords="GCKeyword" template="GCStopArgs" />
		  <event value="2" symbol="GCStop_V1" version="1" task="GC" opcode="win:Stop" level="win:Informational" keywords="GCKeyword" template="GCStopArgs_V1" />
		  <event value="3" symbol="GCRestartEEStop" version="0" task="GC" opcode="RestartEEStop" level="win:Informational" keywords="GCKeyword" />
		  <event value="3" symbol="GCRestartEEStop_V1" version="1" task="GC" opcode="RestartEEStop" level="win:Informational" keywords="GCKeyword" template="GCRestartEEStopArgs_V1" />
		  <event value="4" symbol="GCHeapStats" version="0" task="GC" opcode="HeapStats" level="win:Informational" keywords="GCKeyword" template="GCHeapStatsArgs" />
		  <event value="4" symbol="GCHeapStats_V1" version="1" task="GC" opcode="HeapStats" level="win:Informational" keywords="GCKeyword" template="GCHeapStatsArgs_V1" />
		  <event value="5" symbol="GCCreateSegment" version="0" task="GC" opcode="CreateSegment" level="win:Informational" keywords="GCKeyword" template="GCCreateSegmentArgs" />
		  <event value="5" symbol="GCCreateSegment_V1" version="1" task="GC" opcode="CreateSegment" level="win:Informational" keywords="GCKeyword" template="GCCreateSegmentArgs_V1" />
		  <event value="6" symbol="GCFreeSegment" version="0" task="GC" opcode="FreeSegment" level="win:Informational" keywords="GCKeyword" template="GCFreeSegmentArgs" />
		  <event value="6" symbol="GCFreeSegment_V1" version="1" task="GC" opcode="FreeSegment" level="win:Informational" keywords="GCKeyword" template="GCFreeSegmentArgs_V1" />
		  <event value="7" symbol="GCRestartEEStart" version="0" task="GC" opcode="RestartEEStart" level="win:Informational" keywords="GCKeyword" />
		  <event value="7" symbol="GCRestartEEStart_V1" version="1" task="GC" opcode="RestartEEStart" level="win:Informational" keywords="GCKeyword" template="GCRestartEEStopArgs_V1" />
		  <event value="8" symbol="GCSuspendEEStop" version="0" task="GC" opcode="SuspendEEStop" level="win:Informational" keywords="GCKeyword" />
		  <event value="8" symbol="GCSuspendEEStop_V1" version="1" task="GC" opcode="SuspendEEStop" level="win:Informational" keywords="GCKeyword" template="GCRestartEEStopArgs_V1" />
		  <event value="9" symbol="GCSuspendEEStart" version="0" task="GC" opcode="SuspendEEStart" level="win:Informational" keywords="GCKeyword" template="GCSuspendEEStartArgs" />
		  <event value="9" symbol="GCSuspendEEStart_V1" version="1" task="GC" opcode="SuspendEEStart" level="win:Informational" keywords="GCKeyword" template="GCSuspendEEStartArgs_V1" />
		  <event value="10" symbol="GCAllocationTick" version="0" task="GC" opcode="AllocationTick" level="win:Verbose" keywords="GCKeyword" template="GCAllocationTickArgs" />
		  <event value="10" symbol="GCAllocationTick_V1" version="1" task="GC" opcode="AllocationTick" level="win:Verbose" keywords="GCKeyword" template="GCAllocationTickArgs_V1" />
		  <event value="10" symbol="GCAllocationTick_V2" version="2" task="GC" opcode="AllocationTick" level="win:Verbose" keywords="GCKeyword" template="GCAllocationTickArgs_V2" />
		  <event value="10" symbol="GCAllocationTick_V3" version="3" task="GC" opcode="AllocationTick" level="win:Verbose" keywords="GCKeyword" template="GCAllocationTickArgs_V3" />
		  <event value="11" symbol="GCCreateConcurrentThread" version="0" task="GC" opcode="CreateConcurrentThread" level="win:Informational" keywords="GCKeyword" />
		  <event value="11" symbol="GCCreateConcurrentThread_V1" version="1" task="GC" opcode="CreateConcurrentThread" level="win:Informational" keywords="GCKeyword ThreadingKeyword" template="GCRestartEEStopArgs_V1" />
		  <event value="12" symbol="GCTerminateConcurrentThread" version="0" task="GC" opcode="TerminateConcurrentThread" level="win:Informational" keywords="GCKeyword" />
		  <event value="12" symbol="GCTerminateConcurrentThread_V1" version="1" task="GC" opcode="TerminateConcurrentThread" level="win:Informational" keywords="GCKeyword ThreadingKeyword" template="GCRestartEEStopArgs_V1" />
		  <event value="13" symbol="GCFinalizersStop" version="0" task="GC" opcode="FinalizersStop" level="win:Informational" keywords="GCKeyword" template="GCFinalizersStopArgs" />
		  <event value="13" symbol="GCFinalizersStop_V1" version="1" task="GC" opcode="FinalizersStop" level="win:Informational" keywords="GCKeyword" template="ThreadPoolWorkingThreadCountStartArgs" />
		  <event value="14" symbol="GCFinalizersStart" version="0" task="GC" opcode="FinalizersStart" level="win:Informational" keywords="GCKeyword" />
		  <event value="14" symbol="GCFinalizersStart_V1" version="1" task="GC" opcode="FinalizersStart" level="win:Informational" keywords="GCKeyword" template="GCRestartEEStopArgs_V1" />
		  <event value="15" symbol="TypeBulkType" version="0" task="Type" opcode="BulkType" level="win:Informational" keywords="TypeKeyword" template="TypeBulkTypeArgs" />
		  <event value="16" symbol="GCGCBulkRootEdge" version="0" task="GC" opcode="GCBulkRootEdge" level="win:Informational" keywords="GCHeapDumpKeyword" template="GCGCBulkRootEdgeArgs" />
		  <event value="17" symbol="GCGCBulkRootConditionalWeakTableElementEdge" version="0" task="GC" opcode="GCBulkRootConditionalWeakTableElementEdge" level="win:Informational" keywords="GCHeapDumpKeyword" template="GCGCBulkRootEdgeArgs" />
		  <event value="18" symbol="GCGCBulkNode" version="0" task="GC" opcode="GCBulkNode" level="win:Informational" keywords="GCHeapDumpKeyword" template="GCGCBulkRootEdgeArgs" />
		  <event value="19" symbol="GCGCBulkEdge" version="0" task="GC" opcode="GCBulkEdge" level="win:Informational" keywords="GCHeapDumpKeyword" template="GCGCBulkRootEdgeArgs" />
		  <event value="20" symbol="GCGCSampledObjectAllocation" version="0" task="GC" opcode="GCSampledObjectAllocation" level="win:Informational" keywords="GCSampledObjectAllocationHighKeyword" template="GCGCSampledObjectAllocationArgs" />
		  <event value="21" symbol="GCGCBulkSurvivingObjectRanges" version="0" task="GC" opcode="GCBulkSurvivingObjectRanges" level="win:Informational" keywords="GCHeapSurvivalAndMovementKeyword" template="GCGCBulkRootEdgeArgs" />
		  <event value="22" symbol="GCGCBulkMovedObjectRanges" version="0" task="GC" opcode="GCBulkMovedObjectRanges" level="win:Informational" keywords="GCHeapSurvivalAndMovementKeyword" template="GCGCBulkRootEdgeArgs" />
		  <event value="23" symbol="GCGCGenerationRange" version="0" task="GC" opcode="GCGenerationRange" level="win:Informational" keywords="GCHeapSurvivalAndMovementKeyword" template="GCGCGenerationRangeArgs" />
		  <event value="25" symbol="GCMarkStackRoots" version="0" task="GC" opcode="MarkStackRoots" level="win:Informational" keywords="GCKeyword" template="GCMarkStackRootsArgs" />
		  <event value="26" symbol="GCMarkFinalizeQueueRoots" version="0" task="GC" opcode="MarkFinalizeQueueRoots" level="win:Informational" keywords="GCKeyword" template="GCMarkStackRootsArgs" />
		  <event value="27" symbol="GCMarkHandles" version="0" task="GC" opcode="MarkHandles" level="win:Informational" keywords="GCKeyword" template="GCMarkStackRootsArgs" />
		  <event value="28" symbol="GCMarkCards" version="0" task="GC" opcode="MarkCards" level="win:Informational" keywords="GCKeyword" template="GCMarkStackRootsArgs" />
		  <event value="29" symbol="GCFinalizeObject" version="0" task="GC" opcode="FinalizeObject" level="win:Verbose" keywords="GCKeyword" template="GCFinalizeObjectArgs" />
		  <event value="30" symbol="GCSetGCHandle" version="0" task="GC" opcode="SetGCHandle" level="win:Informational" keywords="GCHandleKeyword" template="GCSetGCHandleArgs" />
		  <event value="31" symbol="GCDestoryGCHandle" version="0" task="GC" opcode="DestoryGCHandle" level="win:Informational" keywords="GCHandleKeyword" template="GCDestoryGCHandleArgs" />
		  <event value="32" symbol="GCGCSampledObjectAllocation32" version="0" task="GC" opcode="GCSampledObjectAllocation" level="win:Informational" keywords="GCSampledObjectAllocationLowKeyword" template="GCGCSampledObjectAllocationArgs" />
		  <event value="33" symbol="GCPinObjectAtGCTime" version="0" task="GC" opcode="PinObjectAtGCTime" level="win:Verbose" keywords="GCKeyword" template="GCPinObjectAtGCTimeArgs" />
		  <event value="35" symbol="GCTriggered" version="0" task="GC" opcode="Triggered" level="win:Informational" keywords="GCKeyword" template="GCTriggeredArgs" />
		  <event value="36" symbol="GCGCBulkRootCCW" version="0" task="GC" opcode="GCBulkRootCCW" level="win:Informational" keywords="GCHeapDumpKeyword" template="TypeBulkTypeArgs" />
		  <event value="37" symbol="GCGCBulkRCW" version="0" task="GC" opcode="GCBulkRCW" level="win:Informational" keywords="GCHeapDumpKeyword" template="TypeBulkTypeArgs" />
		  <event value="38" symbol="GCGCBulkRootStaticVar" version="0" task="GC" opcode="GCBulkRootStaticVar" level="win:Informational" keywords="GCHeapDumpKeyword" template="GCGCBulkRootStaticVarArgs" />
		  <event value="39" symbol="GCGCDynamicEvent" version="0" task="GC" opcode="GCDynamicEvent" level="win:Always" keywords="GCKeyword GCHandleKeyword GCHeapDumpKeyword GCSampledObjectAllocationHighKeyword GCHeapSurvivalAndMovementKeyword GCHeapCollectKeyword GCHeapAndTypeNamesKeyword GCSampledObjectAllocationLowKeyword" template="GCGCDynamicEventArgs" />
		  <event value="40" symbol="WorkerThreadCreationV2Start" version="0" task="WorkerThreadCreationV2" opcode="win:Start" level="win:Informational" keywords="ThreadingKeyword" template="WorkerThreadCreationV2StartArgs" />
		  <event value="41" symbol="WorkerThreadCreationV2Stop" version="0" task="WorkerThreadCreationV2" opcode="win:Stop" level="win:Informational" keywords="ThreadingKeyword" template="WorkerThreadCreationV2StartArgs" />
		  <event value="42" symbol="WorkerThreadRetirementV2Start" version="0" task="WorkerThreadRetirementV2" opcode="win:Start" level="win:Informational" keywords="ThreadingKeyword" template="WorkerThreadCreationV2StartArgs" />
		  <event value="43" symbol="WorkerThreadRetirementV2Stop" version="0" task="WorkerThreadRetirementV2" opcode="win:Stop" level="win:Informational" keywords="ThreadingKeyword" template="WorkerThreadCreationV2StartArgs" />
		  <event value="44" symbol="IOThreadCreationStart" version="0" task="IOThreadCreation" opcode="win:Start" level="win:Informational" keywords="ThreadingKeyword" template="IOThreadCreationStartArgs" />
		  <event value="44" symbol="IOThreadCreationStart_V1" version="1" task="IOThreadCreation" opcode="win:Start" level="win:Informational" keywords="ThreadingKeyword" template="IOThreadCreationStartArgs_V1" />
		  <event value="45" symbol="IOThreadCreationStop" version="0" task="IOThreadCreation" opcode="win:Stop" level="win:Informational" keywords="ThreadingKeyword" template="IOThreadCreationStartArgs" />
		  <event value="45" symbol="IOThreadCreationStop_V1" version="1" task="IOThreadCreation" opcode="win:Stop" level="win:Informational" keywords="ThreadingKeyword" template="IOThreadCreationStartArgs_V1" />
		  <event value="46" symbol="IOThreadRetirementStart" version="0" task="IOThreadRetirement" opcode="win:Start" level="win:Informational" keywords="ThreadingKeyword" template="IOThreadCreationStartArgs" />
		  <event value="46" symbol="IOThreadRetirementStart_V1" version="1" task="IOThreadRetirement" opcode="win:Start" level="win:Informational" keywords="ThreadingKeyword" template="IOThreadCreationStartArgs_V1" />
		  <event value="47" symbol="IOThreadRetirementStop" version="0" task="IOThreadRetirement" opcode="win:Stop" level="win:Informational" keywords="ThreadingKeyword" template="IOThreadCreationStartArgs" />
		  <event value="47" symbol="IOThreadRetirementStop_V1" version="1" task="IOThreadRetirement" opcode="win:Stop" level="win:Informational" keywords="ThreadingKeyword" template="IOThreadCreationStartArgs_V1" />
		  <event value="48" symbol="ThreadpoolSuspensionV2Start" version="0" task="ThreadpoolSuspensionV2" opcode="win:Start" level="win:Informational" keywords="ThreadingKeyword" template="ThreadpoolSuspensionV2StartArgs" />
		  <event value="49" symbol="ThreadpoolSuspensionV2Stop" version="0" task="ThreadpoolSuspensionV2" opcode="win:Stop" level="win:Informational" keywords="ThreadingKeyword" template="ThreadpoolSuspensionV2StartArgs" />
		  <event value="50" symbol="ThreadPoolWorkerThreadStart" version="0" task="ThreadPoolWorkerThread" opcode="win:Start" level="win:Informational" keywords="ThreadingKeyword" template="ThreadPoolWorkerThreadStartArgs" />
		  <event value="51" symbol="ThreadPoolWorkerThreadStop" version="0" task="ThreadPoolWorkerThread" opcode="win:Stop" level="win:Informational" keywords="ThreadingKeyword" template="ThreadPoolWorkerThreadStartArgs" />
		  <event value="52" symbol="ThreadPoolWorkerThreadRetirementStart" version="0" task="ThreadPoolWorkerThreadRetirement" opcode="win:Start" level="win:Informational" keywords="ThreadingKeyword" template="ThreadPoolWorkerThreadStartArgs" />
		  <event value="53" symbol="ThreadPoolWorkerThreadRetirementStop" version="0" task="ThreadPoolWorkerThreadRetirement" opcode="win:Stop" level="win:Informational" keywords="ThreadingKeyword" template="ThreadPoolWorkerThreadStartArgs" />
		  <event value="54" symbol="ThreadPoolWorkerThreadAdjustmentSample" version="0" task="ThreadPoolWorkerThreadAdjustment" opcode="Sample" level="win:Informational" keywords="ThreadingKeyword" template="ThreadPoolWorkerThreadAdjustmentSampleArgs" />
		  <event value="55" symbol="ThreadPoolWorkerThreadAdjustment" version="0" task="ThreadPoolWorkerThreadAdjustment" opcode="Adjustment" level="win:Informational" keywords="ThreadingKeyword" template="ThreadPoolWorkerThreadAdjustmentArgs" />
		  <event value="56" symbol="ThreadPoolWorkerThreadAdjustmentStats" version="0" task="ThreadPoolWorkerThreadAdjustment" opcode="Stats" level="win:Verbose" keywords="ThreadingKeyword" template="ThreadPoolWorkerThreadAdjustmentStatsArgs" />
		  <event value="57" symbol="ThreadPoolWorkerThreadWait" version="0" task="ThreadPoolWorkerThread" opcode="Wait" level="win:Informational" keywords="ThreadingKeyword" template="ThreadPoolWorkerThreadStartArgs" />
		  <event value="60" symbol="ThreadPoolWorkingThreadCountStart" version="0" task="ThreadPoolWorkingThreadCount" opcode="win:Start" level="win:Verbose" keywords="ThreadingKeyword" template="ThreadPoolWorkingThreadCountStartArgs" />
		  <event value="61" symbol="ThreadPoolEnqueue" version="0" task="ThreadPool" opcode="Enqueue" level="win:Verbose" keywords="ThreadingKeyword ThreadTransferKeyword" template="ThreadPoolEnqueueArgs" />
		  <event value="62" symbol="ThreadPoolDequeue" version="0" task="ThreadPool" opcode="Dequeue" level="win:Verbose" keywords="ThreadingKeyword ThreadTransferKeyword" template="ThreadPoolEnqueueArgs" />
		  <event value="63" symbol="ThreadPoolIOEnqueue" version="0" task="ThreadPool" opcode="IOEnqueue" level="win:Verbose" keywords="ThreadingKeyword ThreadTransferKeyword" template="ThreadPoolIOEnqueueArgs" />
		  <event value="64" symbol="ThreadPoolIODequeue" version="0" task="ThreadPool" opcode="IODequeue" level="win:Verbose" keywords="ThreadingKeyword ThreadTransferKeyword" template="ThreadPoolIODequeueArgs" />
		  <event value="65" symbol="ThreadPoolIOPack" version="0" task="ThreadPool" opcode="IOPack" level="win:Verbose" keywords="ThreadingKeyword" template="ThreadPoolIODequeueArgs" />
		  <event value="70" symbol="ThreadCreating" version="0" task="Thread" opcode="Creating" level="win:Informational" keywords="ThreadingKeyword ThreadTransferKeyword" template="ThreadCreatingArgs" />
		  <event value="71" symbol="ThreadRunning" version="0" task="Thread" opcode="Running" level="win:Informational" keywords="ThreadingKeyword ThreadTransferKeyword" template="ThreadCreatingArgs" />
		  <event value="80" symbol="ExceptionStart" version="0" task="Exception" opcode="win:Start" level="win:Informational" />
		  <event value="80" symbol="ExceptionStart_V1" version="1" task="Exception" opcode="win:Start" level="win:Error" keywords="ExceptionKeyword MonitoringKeyword" template="ExceptionStartArgs_V1" />
		  <event value="81" symbol="ContentionStart" version="0" task="Contention" opcode="win:Start" level="win:Informational" />
		  <event value="81" symbol="ContentionStart_V1" version="1" task="Contention" opcode="win:Start" level="win:Informational" keywords="ContentionKeyword" template="ContentionStartArgs_V1" />
		  <event value="82" symbol="ClrStackWalk" version="0" task="ClrStack" opcode="Walk" level="win:Always" keywords="StackKeyword" template="ClrStackWalkArgs" />
		  <event value="83" symbol="AppDomainResourceManagementMemAllocated" version="0" task="AppDomainResourceManagement" opcode="MemAllocated" level="win:Informational" keywords="AppDomainResourceManagementKeyword" template="AppDomainResourceManagementMemAllocatedArgs" />
		  <event value="84" symbol="AppDomainResourceManagementMemSurvived" version="0" task="AppDomainResourceManagement" opcode="MemSurvived" level="win:Informational" keywords="AppDomainResourceManagementKeyword" template="AppDomainResourceManagementMemSurvivedArgs" />
		  <event value="85" symbol="AppDomainResourceManagementThreadCreated" version="0" task="AppDomainResourceManagement" opcode="ThreadCreated" level="win:Informational" keywords="AppDomainResourceManagementKeyword ThreadingKeyword" template="AppDomainResourceManagementThreadCreatedArgs" />
		  <event value="86" symbol="AppDomainResourceManagementThreadTerminated" version="0" task="AppDomainResourceManagement" opcode="ThreadTerminated" level="win:Informational" keywords="AppDomainResourceManagementKeyword ThreadingKeyword" template="AppDomainResourceManagementThreadTerminatedArgs" />
		  <event value="87" symbol="AppDomainResourceManagementDomainEnter" version="0" task="AppDomainResourceManagement" opcode="DomainEnter" level="win:Informational" keywords="AppDomainResourceManagementKeyword ThreadingKeyword" template="AppDomainResourceManagementThreadTerminatedArgs" />
		  <event value="88" symbol="ILStubStubGenerated" version="0" task="ILStub" opcode="StubGenerated" level="win:Informational" keywords="InteropKeyword" template="ILStubStubGeneratedArgs" />
		  <event value="89" symbol="ILStubStubCacheHit" version="0" task="ILStub" opcode="StubCacheHit" level="win:Informational" keywords="InteropKeyword" template="ILStubStubCacheHitArgs" />
		  <event value="91" symbol="ContentionStop" version="0" task="Contention" opcode="win:Stop" level="win:Informational" keywords="ContentionKeyword" template="ContentionStopArgs" />
		  <event value="135" symbol="MethodDCStartCompleteV2" version="0" task="Method" opcode="DCStartCompleteV2" level="win:Informational" keywords="JitKeyword NGenKeyword" />
		  <event value="136" symbol="MethodDCEndCompleteV2" version="0" task="Method" opcode="DCEndCompleteV2" level="win:Informational" keywords="JitKeyword NGenKeyword" />
		  <event value="137" symbol="MethodDCStartV2" version="0" task="Method" opcode="DCStartV2" level="win:Informational" keywords="JitKeyword NGenKeyword" template="MethodDCStartV2Args" />
		  <event value="138" symbol="MethodDCStopV2" version="0" task="Method" opcode="DCStopV2" level="win:Informational" keywords="JitKeyword NGenKeyword" template="MethodDCStopV2Args" />
		  <event value="139" symbol="MethodDCStartVerboseV2" version="0" task="Method" opcode="DCStartVerboseV2" level="win:Informational" keywords="JitKeyword NGenKeyword" template="MethodDCStartVerboseV2Args" />
		  <event value="140" symbol="MethodDCStopVerboseV2" version="0" task="Method" opcode="DCStopVerboseV2" level="win:Informational" keywords="JitKeyword NGenKeyword" template="MethodDCStartVerboseV2Args" />
		  <event value="141" symbol="MethodLoad" version="0" task="Method" opcode="Load" level="win:Informational" keywords="JitKeyword NGenKeyword" template="MethodDCStartV2Args" />
		  <event value="141" symbol="MethodLoad_V1" version="1" task="Method" opcode="Load" level="win:Informational" keywords="JitKeyword NGenKeyword" template="MethodLoadArgs_V1" />
		  <event value="141" symbol="MethodLoad_V2" version="2" task="Method" opcode="Load" level="win:Informational" keywords="JitKeyword NGenKeyword" template="MethodLoadArgs_V2" />
		  <event value="142" symbol="MethodUnload" version="0" task="Method" opcode="Unload" level="win:Informational" keywords="JitKeyword NGenKeyword" template="MethodDCStartV2Args" />
		  <event value="142" symbol="MethodUnload_V1" version="1" task="Method" opcode="Unload" level="win:Informational" keywords="JitKeyword NGenKeyword" template="MethodLoadArgs_V1" />
		  <event value="142" symbol="MethodUnload_V2" version="2" task="Method" opcode="Unload" level="win:Informational" keywords="JitKeyword NGenKeyword" template="MethodLoadArgs_V2" />
		  <event value="143" symbol="MethodLoadVerbose" version="0" task="Method" opcode="LoadVerbose" level="win:Informational" keywords="JitKeyword NGenKeyword" template="MethodDCStartVerboseV2Args" />
		  <event value="143" symbol="MethodLoadVerbose_V1" version="1" task="Method" opcode="LoadVerbose" level="win:Informational" keywords="JitKeyword NGenKeyword" template="MethodLoadVerboseArgs_V1" />
		  <event value="143" symbol="MethodLoadVerbose_V2" version="2" task="Method" opcode="LoadVerbose" level="win:Informational" keywords="JitKeyword NGenKeyword" template="MethodLoadVerboseArgs_V2" />
		  <event value="144" symbol="MethodUnloadVerbose" version="0" task="Method" opcode="UnloadVerbose" level="win:Informational" keywords="JitKeyword NGenKeyword" template="MethodDCStartVerboseV2Args" />
		  <event value="144" symbol="MethodUnloadVerbose_V1" version="1" task="Method" opcode="UnloadVerbose" level="win:Informational" keywords="JitKeyword NGenKeyword" template="MethodLoadVerboseArgs_V1" />
		  <event value="144" symbol="MethodUnloadVerbose_V2" version="2" task="Method" opcode="UnloadVerbose" level="win:Informational" keywords="JitKeyword NGenKeyword" template="MethodLoadVerboseArgs_V2" />
		  <event value="145" symbol="MethodJittingStarted" version="0" task="Method" opcode="JittingStarted" level="win:Verbose" keywords="JitKeyword" template="MethodJittingStartedArgs" />
		  <event value="145" symbol="MethodJittingStarted_V1" version="1" task="Method" opcode="JittingStarted" level="win:Verbose" keywords="JitKeyword" template="MethodJittingStartedArgs_V1" />
		  <event value="149" symbol="LoaderModuleDCStartV2" version="0" task="Loader" opcode="ModuleDCStartV2" level="win:Informational" keywords="LoaderKeyword" template="LoaderModuleDCStartV2Args" />
		  <event value="150" symbol="LoaderModuleDCStopV2" version="0" task="Loader" opcode="ModuleDCStopV2" level="win:Informational" keywords="LoaderKeyword" template="LoaderModuleDCStopV2Args" />
		  <event value="151" symbol="LoaderDomainModuleLoad" version="0" task="Loader" opcode="DomainModuleLoad" level="win:Informational" keywords="LoaderKeyword" template="LoaderDomainModuleLoadArgs" />
		  <event value="151" symbol="LoaderDomainModuleLoad_V1" version="1" task="Loader" opcode="DomainModuleLoad" level="win:Informational" keywords="LoaderKeyword" template="LoaderDomainModuleLoadArgs_V1" />
		  <event value="152" symbol="LoaderModuleLoad" version="0" task="Loader" opcode="ModuleLoad" level="win:Informational" keywords="LoaderKeyword" template="LoaderModuleDCStopV2Args" />
		  <event value="152" symbol="LoaderModuleLoad_V1" version="1" task="Loader" opcode="ModuleLoad" level="win:Informational" keywords="LoaderKeyword PerfTrackKeyword" template="LoaderModuleLoadArgs_V1" />
		  <event value="152" symbol="LoaderModuleLoad_V2" version="2" task="Loader" opcode="ModuleLoad" level="win:Informational" keywords="LoaderKeyword PerfTrackKeyword" template="LoaderModuleLoadArgs_V2" />
		  <event value="153" symbol="LoaderModuleUnload" version="0" task="Loader" opcode="ModuleUnload" level="win:Informational" keywords="LoaderKeyword" template="LoaderModuleDCStopV2Args" />
		  <event value="153" symbol="LoaderModuleUnload_V1" version="1" task="Loader" opcode="ModuleUnload" level="win:Informational" keywords="LoaderKeyword PerfTrackKeyword" template="LoaderModuleLoadArgs_V1" />
		  <event value="153" symbol="LoaderModuleUnload_V2" version="2" task="Loader" opcode="ModuleUnload" level="win:Informational" keywords="LoaderKeyword PerfTrackKeyword" template="LoaderModuleLoadArgs_V2" />
		  <event value="154" symbol="LoaderAssemblyLoad" version="0" task="Loader" opcode="AssemblyLoad" level="win:Informational" keywords="LoaderKeyword" template="LoaderAssemblyLoadArgs" />
		  <event value="154" symbol="LoaderAssemblyLoad_V1" version="1" task="Loader" opcode="AssemblyLoad" level="win:Informational" keywords="LoaderKeyword" template="LoaderAssemblyLoadArgs_V1" />
		  <event value="155" symbol="LoaderAssemblyUnload" version="0" task="Loader" opcode="AssemblyUnload" level="win:Informational" keywords="LoaderKeyword" template="LoaderAssemblyUnloadArgs" />
		  <event value="155" symbol="LoaderAssemblyUnload_V1" version="1" task="Loader" opcode="AssemblyUnload" level="win:Informational" keywords="LoaderKeyword" template="LoaderAssemblyLoadArgs_V1" />
		  <event value="156" symbol="LoaderAppDomainLoad" version="0" task="Loader" opcode="AppDomainLoad" level="win:Informational" keywords="LoaderKeyword" template="LoaderAppDomainLoadArgs" />
		  <event value="156" symbol="LoaderAppDomainLoad_V1" version="1" task="Loader" opcode="AppDomainLoad" level="win:Informational" keywords="LoaderKeyword" template="LoaderAppDomainLoadArgs_V1" />
		  <event value="157" symbol="LoaderAppDomainUnload" version="0" task="Loader" opcode="AppDomainUnload" level="win:Informational" keywords="LoaderKeyword" template="LoaderAppDomainUnloadArgs" />
		  <event value="157" symbol="LoaderAppDomainUnload_V1" version="1" task="Loader" opcode="AppDomainUnload" level="win:Informational" keywords="LoaderKeyword" template="LoaderAppDomainLoadArgs_V1" />
		  <event value="158" symbol="ClrPerfTrackModuleRangeLoad" version="0" task="ClrPerfTrack" opcode="ModuleRangeLoad" level="win:Informational" keywords="PerfTrackKeyword" template="ClrPerfTrackModuleRangeLoadArgs" />
		  <event value="181" symbol="StrongNameVerificationStart" version="0" task="StrongNameVerification" opcode="win:Start" level="win:Verbose" keywords="SecurityKeyword" template="StrongNameVerificationStartArgs" />
		  <event value="181" symbol="StrongNameVerificationStart_V1" version="1" task="StrongNameVerification" opcode="win:Start" level="win:Verbose" keywords="SecurityKeyword" template="StrongNameVerificationStartArgs_V1" />
		  <event value="182" symbol="StrongNameVerificationStop" version="0" task="StrongNameVerification" opcode="win:Stop" level="win:Informational" keywords="SecurityKeyword" template="StrongNameVerificationStartArgs" />
		  <event value="182" symbol="StrongNameVerificationStop_V1" version="1" task="StrongNameVerification" opcode="win:Stop" level="win:Informational" keywords="SecurityKeyword" template="StrongNameVerificationStartArgs_V1" />
		  <event value="183" symbol="AuthenticodeVerificationStart" version="0" task="AuthenticodeVerification" opcode="win:Start" level="win:Verbose" keywords="SecurityKeyword" template="AuthenticodeVerificationStartArgs" />
		  <event value="183" symbol="AuthenticodeVerificationStart_V1" version="1" task="AuthenticodeVerification" opcode="win:Start" level="win:Verbose" keywords="SecurityKeyword" template="AuthenticodeVerificationStartArgs_V1" />
		  <event value="184" symbol="AuthenticodeVerificationStop" version="0" task="AuthenticodeVerification" opcode="win:Stop" level="win:Informational" keywords="SecurityKeyword" template="AuthenticodeVerificationStartArgs" />
		  <event value="184" symbol="AuthenticodeVerificationStop_V1" version="1" task="AuthenticodeVerification" opcode="win:Stop" level="win:Informational" keywords="SecurityKeyword" template="AuthenticodeVerificationStartArgs_V1" />
		  <event value="185" symbol="MethodInliningSucceeded" version="0" task="Method" opcode="InliningSucceeded" level="win:Verbose" keywords="JitTracingKeyword" template="MethodInliningSucceededArgs" />
		  <event value="186" symbol="MethodInliningFailed" version="0" task="Method" opcode="InliningFailed" level="win:Verbose" keywords="JitTracingKeyword" template="MethodInliningFailedArgs" />
		  <event value="187" symbol="RuntimeStart" version="0" task="Runtime" opcode="win:Start" level="win:Informational" template="RuntimeStartArgs" />
		  <event value="188" symbol="MethodTailCallSucceeded" version="0" task="Method" opcode="TailCallSucceeded" level="win:Verbose" keywords="JitTracingKeyword" template="MethodTailCallSucceededArgs" />
		  <event value="189" symbol="MethodTailCallFailed" version="0" task="Method" opcode="TailCallFailed" level="win:Verbose" keywords="JitTracingKeyword" template="MethodTailCallFailedArgs" />
		  <event value="190" symbol="MethodMethodILToNativeMap" version="0" task="Method" opcode="MethodILToNativeMap" level="win:Verbose" keywords="JittedMethodILToNativeMapKeyword" template="MethodMethodILToNativeMapArgs" />
		  <event value="200" symbol="GCIncreaseMemoryPressure" version="0" task="GC" opcode="IncreaseMemoryPressure" level="win:Verbose" keywords="GCKeyword" template="GCIncreaseMemoryPressureArgs" />
		  <event value="201" symbol="GCDecreaseMemoryPressure" version="0" task="GC" opcode="DecreaseMemoryPressure" level="win:Verbose" keywords="GCKeyword" template="GCDecreaseMemoryPressureArgs" />
		  <event value="202" symbol="GCMark" version="0" task="GC" opcode="Mark" level="win:Informational" keywords="GCKeyword" template="GCMarkArgs" />
		  <event value="203" symbol="GCGCJoin_V2" version="2" task="GC" opcode="GCJoin" level="win:Verbose" keywords="GCKeyword" template="GCGCJoinArgs_V2" />
		  <event value="204" symbol="GCPerHeapHistory_V3" version="3" task="GC" opcode="PerHeapHistory" level="win:Informational" keywords="GCKeyword" template="GCPerHeapHistoryArgs_V3" />
		  <event value="205" symbol="GCGlobalHeapHistory_V2" version="2" task="GC" opcode="GlobalHeapHistory" level="win:Informational" keywords="GCKeyword" template="GCGlobalHeapHistoryArgs_V2" />
		  <event value="206" symbol="GCGCLoaded" version="0" task="GC" opcode="GCLoaded" level="win:Informational" keywords="GCKeyword" template="GCGCLoadedArgs" />
		  <event value="240" symbol="DebugIPCEventStart" version="0" task="DebugIPCEvent" opcode="win:Start" level="win:Informational" keywords="DebuggerKeyword" />
		  <event value="241" symbol="DebugIPCEventStop" version="0" task="DebugIPCEvent" opcode="win:Stop" level="win:Informational" keywords="DebuggerKeyword" />
		  <event value="242" symbol="DebugExceptionProcessingStart" version="0" task="DebugExceptionProcessing" opcode="win:Start" level="win:Informational" keywords="DebuggerKeyword" />
		  <event value="243" symbol="DebugExceptionProcessingStop" version="0" task="DebugExceptionProcessing" opcode="win:Stop" level="win:Informational" keywords="DebuggerKeyword" />
		  <event value="250" symbol="ExceptionCatchStart" version="0" task="ExceptionCatch" opcode="win:Start" level="win:Informational" keywords="ExceptionKeyword" template="ExceptionCatchStartArgs" />
		  <event value="251" symbol="ExceptionCatchStop" version="0" task="ExceptionCatch" opcode="win:Stop" level="win:Informational" keywords="ExceptionKeyword" />
		  <event value="252" symbol="ExceptionFinallyStart" version="0" task="ExceptionFinally" opcode="win:Start" level="win:Informational" keywords="ExceptionKeyword" template="ExceptionCatchStartArgs" />
		  <event value="253" symbol="ExceptionFinallyStop" version="0" task="ExceptionFinally" opcode="win:Stop" level="win:Informational" keywords="ExceptionKeyword" />
		  <event value="254" symbol="ExceptionFilterStart" version="0" task="ExceptionFilter" opcode="win:Start" level="win:Informational" keywords="ExceptionKeyword" template="ExceptionCatchStartArgs" />
		  <event value="255" symbol="ExceptionFilterStop" version="0" task="ExceptionFilter" opcode="win:Stop" level="win:Informational" keywords="ExceptionKeyword" />
		  <event value="256" symbol="ExceptionStop" version="0" task="Exception" opcode="win:Stop" level="win:Informational" keywords="ExceptionKeyword" />
		</events>
#  Eventid와 EventName(symbol)매핑
```
*/