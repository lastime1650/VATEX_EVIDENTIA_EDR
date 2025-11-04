#ifndef DOTNET_RUNETIME_ETW_CALLBACKS_HPP
#define DOTNET_RUNETIME_ETW_CALLBACKS_HPP


#include "ETW_Providers.hpp"

#include <string>
#include <iostream>

#include <krabs.hpp>

#include "EventLog.hpp"

namespace EDR
{
    namespace ETW
    {
        namespace DOTNET
        {
            namespace Callback
            {
                
                

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
                std::wstring get_gc_reason_string(uint32_t reason) {
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

                class DotNetEventCallbackCls
                {
                public:
                    DotNetEventCallbackCls(EDR::Util::Queue::IQueue& Queue)
                        :Queue(Queue)
                    {}
                    ~DotNetEventCallbackCls() = default;

                    static void dotnet_event_callback(const EVENT_RECORD& record, const krabs::trace_context& context)
                    {
                        return _dotnet_event_callback(record, context);
                    }
                private:
                    EDR::Util::Queue::IQueue& Queue;


					static void _dotnet_event_callback(const EVENT_RECORD& record, const krabs::trace_context& context) {
						krabs::schema schema(record, context.schema_locator);
						krabs::parser parser(schema);

						EDR::EventLog::Struct::ETW::ETW_Log_Struct ELS;
						RtlZeroMemory(&ELS, sizeof(EDR::EventLog::Struct::ETW::ETW_Log_Struct));

						ELS.header.ProcessId = (HANDLE)( (ULONG64)schema.process_id() );

						std::wstring eventNameW = schema.event_name();
						std::string eventNameA = EDR::Util::wchar_to_char(eventNameW.c_str());
						RtlCopyMemory(ELS.EventName, eventNameA.c_str(), eventNameA.length() );

						ELS.EventId = schema.event_id();
						ELS.EventFlags = schema.event_flags();
						ELS.EventVersion = schema.event_version();

						std::string providerName = "Microsoft-Windows-DotNetRuntime";
						RtlCopyMemory(ELS.ProviderName, providerName.c_str(), providerName.length());


						int field_idx = 0;

						switch (schema.event_id())
						{
							case 1:
							{
								if (schema.event_version() == 0)
								{
									auto Count = safe_parse<uint32_t>(parser, L"Count");
									auto Reason = safe_parse<uint32_t>(parser, L"Reason");
									ELS.field.FieldCount = 2;
									std::string Count_str = std::to_string(Count);
									std::string Reason_str = std::to_string(Reason);
									RtlCopyMemory(ELS.field.Fields[0].FieldName, "Count", sizeof("Count"));
									RtlCopyMemory(ELS.field.Fields[0].FieldValue, Count_str.c_str(), Count_str.length());
									RtlCopyMemory(ELS.field.Fields[1].FieldName, "Reason", sizeof("Reason"));
									RtlCopyMemory(ELS.field.Fields[1].FieldValue, Reason_str.c_str(), Reason_str.length());
								}
								else if (schema.event_version() == 1)
								{
									auto Count = safe_parse<uint32_t>(parser, L"Count");
									auto Depth = safe_parse<uint32_t>(parser, L"Depth");
									auto Reason = safe_parse<uint32_t>(parser, L"Reason");
									auto Type = safe_parse<uint32_t>(parser, L"Type");
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS.field.FieldCount = 5;
									std::string Count_str = std::to_string(Count);
									std::string Depth_str = std::to_string(Depth);
									std::string Reason_str = std::to_string(Reason);
									std::string Type_str = std::to_string(Type);
									std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS.field.Fields[0].FieldName, "Count", sizeof("Count"));
									RtlCopyMemory(ELS.field.Fields[0].FieldValue, Count_str.c_str(), Count_str.length());
									RtlCopyMemory(ELS.field.Fields[1].FieldName, "Depth", sizeof("Depth"));
									RtlCopyMemory(ELS.field.Fields[1].FieldValue, Depth_str.c_str(), Depth_str.length());
									RtlCopyMemory(ELS.field.Fields[2].FieldName, "Reason", sizeof("Reason"));
									RtlCopyMemory(ELS.field.Fields[2].FieldValue, Reason_str.c_str(), Reason_str.length());
									RtlCopyMemory(ELS.field.Fields[3].FieldName, "Type", sizeof("Type"));
									RtlCopyMemory(ELS.field.Fields[3].FieldValue, Type_str.c_str(), Type_str.length());
									RtlCopyMemory(ELS.field.Fields[4].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
									RtlCopyMemory(ELS.field.Fields[4].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								}
								else if (schema.event_version() == 2)
								{
									auto Count = safe_parse<uint32_t>(parser, L"Count");
									auto Depth = safe_parse<uint32_t>(parser, L"Depth");
									auto Reason = safe_parse<uint32_t>(parser, L"Reason");
									auto Type = safe_parse<uint32_t>(parser, L"Type");
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									auto ClientSequenceNumber = safe_parse<uint64_t>(parser, L"ClientSequenceNumber");
									ELS.field.FieldCount = 6;
									std::string Count_str = std::to_string(Count);
									std::string Depth_str = std::to_string(Depth);
									std::string Reason_str = std::to_string(Reason);
									std::string Type_str = std::to_string(Type);
									std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
									std::string ClientSequenceNumber_str = std::to_string(ClientSequenceNumber);
									RtlCopyMemory(ELS.field.Fields[0].FieldName, "Count", sizeof("Count"));
									RtlCopyMemory(ELS.field.Fields[0].FieldValue, Count_str.c_str(), Count_str.length());
									RtlCopyMemory(ELS.field.Fields[1].FieldName, "Depth", sizeof("Depth"));
									RtlCopyMemory(ELS.field.Fields[1].FieldValue, Depth_str.c_str(), Depth_str.length());
									RtlCopyMemory(ELS.field.Fields[2].FieldName, "Reason", sizeof("Reason"));
									RtlCopyMemory(ELS.field.Fields[2].FieldValue, Reason_str.c_str(), Reason_str.length());
									RtlCopyMemory(ELS.field.Fields[3].FieldName, "Type", sizeof("Type"));
									RtlCopyMemory(ELS.field.Fields[3].FieldValue, Type_str.c_str(), Type_str.length());
									RtlCopyMemory(ELS.field.Fields[4].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
									RtlCopyMemory(ELS.field.Fields[4].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
									RtlCopyMemory(ELS.field.Fields[5].FieldName, "ClientSequenceNumber", sizeof("ClientSequenceNumber"));
									RtlCopyMemory(ELS.field.Fields[5].FieldValue, ClientSequenceNumber_str.c_str(), ClientSequenceNumber_str.length());
								}
								break;
							}
							case 2:
							{
								if (schema.event_version() == 0)
								{
									auto Count = safe_parse<uint32_t>(parser, L"Count");
									auto Depth = safe_parse<uint16_t>(parser, L"Depth");
									ELS.field.FieldCount = 2;
									std::string Count_str = std::to_string(Count);
									std::string Depth_str = std::to_string(Depth);
									RtlCopyMemory(ELS.field.Fields[0].FieldName, "Count", sizeof("Count"));
									RtlCopyMemory(ELS.field.Fields[0].FieldValue, Count_str.c_str(), Count_str.length());
									RtlCopyMemory(ELS.field.Fields[1].FieldName, "Depth", sizeof("Depth"));
									RtlCopyMemory(ELS.field.Fields[1].FieldValue, Depth_str.c_str(), Depth_str.length());
								}
								else if (schema.event_version() == 1)
								{
									auto Count = safe_parse<uint32_t>(parser, L"Count");
									auto Depth = safe_parse<uint32_t>(parser, L"Depth");
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS.field.FieldCount = 3;
									std::string Count_str = std::to_string(Count);
									std::string Depth_str = std::to_string(Depth);
									std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS.field.Fields[0].FieldName, "Count", sizeof("Count"));
									RtlCopyMemory(ELS.field.Fields[0].FieldValue, Count_str.c_str(), Count_str.length());
									RtlCopyMemory(ELS.field.Fields[1].FieldName, "Depth", sizeof("Depth"));
									RtlCopyMemory(ELS.field.Fields[1].FieldValue, Depth_str.c_str(), Depth_str.length());
									RtlCopyMemory(ELS.field.Fields[2].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
									RtlCopyMemory(ELS.field.Fields[2].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								}
								break;
							}
							case 3:
							{
								if (schema.event_version() == 1)
								{
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS.field.FieldCount = 1;
									std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS.field.Fields[0].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
									RtlCopyMemory(ELS.field.Fields[0].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								}
								break;
							}
							case 4:
							{
								if (schema.event_version() == 0 || schema.event_version() == 1)
								{
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

									field_idx = 0;
									RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "GenerationSize0", sizeof("GenerationSize0"));
									std::string GenSize0_str = std::to_string(GenerationSize0);
									RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, GenSize0_str.c_str(), GenSize0_str.length());

									RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "TotalPromotedSize0", sizeof("TotalPromotedSize0"));
									std::string Promoted0_str = std::to_string(TotalPromotedSize0);
									RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, Promoted0_str.c_str(), Promoted0_str.length());

									RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "GenerationSize1", sizeof("GenerationSize1"));
									std::string GenSize1_str = std::to_string(GenerationSize1);
									RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, GenSize1_str.c_str(), GenSize1_str.length());

									RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "TotalPromotedSize1", sizeof("TotalPromotedSize1"));
									std::string Promoted1_str = std::to_string(TotalPromotedSize1);
									RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, Promoted1_str.c_str(), Promoted1_str.length());

									RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "GenerationSize2", sizeof("GenerationSize2"));
									std::string GenSize2_str = std::to_string(GenerationSize2);
									RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, GenSize2_str.c_str(), GenSize2_str.length());

									RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "TotalPromotedSize2", sizeof("TotalPromotedSize2"));
									std::string Promoted2_str = std::to_string(TotalPromotedSize2);
									RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, Promoted2_str.c_str(), Promoted2_str.length());

									RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "GenerationSize3", sizeof("GenerationSize3"));
									std::string GenSize3_str = std::to_string(GenerationSize3);
									RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, GenSize3_str.c_str(), GenSize3_str.length());

									RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "TotalPromotedSize3", sizeof("TotalPromotedSize3"));
									std::string Promoted3_str = std::to_string(TotalPromotedSize3);
									RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, Promoted3_str.c_str(), Promoted3_str.length());

									RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "FinalizationPromotedSize", sizeof("FinalizationPromotedSize"));
									std::string FinalPromotedSize_str = std::to_string(FinalizationPromotedSize);
									RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, FinalPromotedSize_str.c_str(), FinalPromotedSize_str.length());

									RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "FinalizationPromotedCount", sizeof("FinalizationPromotedCount"));
									std::string FinalPromotedCount_str = std::to_string(FinalizationPromotedCount);
									RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, FinalPromotedCount_str.c_str(), FinalPromotedCount_str.length());

									RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "PinnedObjectCount", sizeof("PinnedObjectCount"));
									std::string PinnedCount_str = std::to_string(PinnedObjectCount);
									RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, PinnedCount_str.c_str(), PinnedCount_str.length());

									RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "SinkBlockCount", sizeof("SinkBlockCount"));
									std::string SinkCount_str = std::to_string(SinkBlockCount);
									RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, SinkCount_str.c_str(), SinkCount_str.length());

									RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "GCHandleCount", sizeof("GCHandleCount"));
									std::string HandleCount_str = std::to_string(GCHandleCount);
									RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, HandleCount_str.c_str(), HandleCount_str.length());

									if (schema.event_version() == 1)
									{
										auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
										std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
										RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
										RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
									}
									ELS.field.FieldCount = field_idx;
								}
								break;
							}
							case 5:
							{
								if (schema.event_version() == 0 || schema.event_version() == 1)
								{
									auto Address = safe_parse<uint64_t>(parser, L"Address");
									auto Size = safe_parse<uint64_t>(parser, L"Size");
									auto Type = safe_parse<uint32_t>(parser, L"Type");
									ELS.field.FieldCount = 3;
									std::string Address_str = std::to_string(Address);
									std::string Size_str = std::to_string(Size);
									std::string Type_str = std::to_string(Type);
									RtlCopyMemory(ELS.field.Fields[0].FieldName, "Address", sizeof("Address"));
									RtlCopyMemory(ELS.field.Fields[0].FieldValue, Address_str.c_str(), Address_str.length());
									RtlCopyMemory(ELS.field.Fields[1].FieldName, "Size", sizeof("Size"));
									RtlCopyMemory(ELS.field.Fields[1].FieldValue, Size_str.c_str(), Size_str.length());
									RtlCopyMemory(ELS.field.Fields[2].FieldName, "Type", sizeof("Type"));
									RtlCopyMemory(ELS.field.Fields[2].FieldValue, Type_str.c_str(), Type_str.length());
									if (schema.event_version() == 1)
									{
										auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
										ELS.field.FieldCount = 4;
										std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
										RtlCopyMemory(ELS.field.Fields[3].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
										RtlCopyMemory(ELS.field.Fields[3].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
									}
								}
								break;
							}
							case 6:
							{
								if (schema.event_version() == 0 || schema.event_version() == 1)
								{
									auto Address = safe_parse<uint64_t>(parser, L"Address");
									ELS.field.FieldCount = 1;
									std::string Address_str = std::to_string(Address);
									RtlCopyMemory(ELS.field.Fields[0].FieldName, "Address", sizeof("Address"));
									RtlCopyMemory(ELS.field.Fields[0].FieldValue, Address_str.c_str(), Address_str.length());
									if (schema.event_version() == 1)
									{
										auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
										ELS.field.FieldCount = 2;
										std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
										RtlCopyMemory(ELS.field.Fields[1].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
										RtlCopyMemory(ELS.field.Fields[1].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
									}
								}
								break;
							}
							case 7:
							{
								if (schema.event_version() == 1)
								{
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS.field.FieldCount = 1;
									std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS.field.Fields[0].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
									RtlCopyMemory(ELS.field.Fields[0].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								}
								break;
							}
							case 8:
							{
								if (schema.event_version() == 1)
								{
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS.field.FieldCount = 1;
									std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS.field.Fields[0].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
									RtlCopyMemory(ELS.field.Fields[0].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								}
								break;
							}
							case 9:
							{
								if (schema.event_version() == 0)
								{
									auto Reason = safe_parse<uint16_t>(parser, L"Reason");
									ELS.field.FieldCount = 1;
									std::string Reason_str = std::to_string(Reason);
									RtlCopyMemory(ELS.field.Fields[0].FieldName, "Reason", sizeof("Reason"));
									RtlCopyMemory(ELS.field.Fields[0].FieldValue, Reason_str.c_str(), Reason_str.length());
								}
								else if (schema.event_version() == 1)
								{
									auto Reason = safe_parse<uint32_t>(parser, L"Reason");
									auto Count = safe_parse<uint32_t>(parser, L"Count");
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS.field.FieldCount = 3;
									std::string Reason_str = std::to_string(Reason);
									std::string Count_str = std::to_string(Count);
									std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS.field.Fields[0].FieldName, "Reason", sizeof("Reason"));
									RtlCopyMemory(ELS.field.Fields[0].FieldValue, Reason_str.c_str(), Reason_str.length());
									RtlCopyMemory(ELS.field.Fields[1].FieldName, "Count", sizeof("Count"));
									RtlCopyMemory(ELS.field.Fields[1].FieldValue, Count_str.c_str(), Count_str.length());
									RtlCopyMemory(ELS.field.Fields[2].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
									RtlCopyMemory(ELS.field.Fields[2].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								}
								break;
							}
							case 10:
							{
								if (schema.event_version() == 0 || schema.event_version() == 1)
								{
									auto AllocationAmount = safe_parse<uint32_t>(parser, L"AllocationAmount");
									auto AllocationKind = safe_parse<uint32_t>(parser, L"AllocationKind");
									ELS.field.FieldCount = 2;
									std::string AllocationAmount_str = std::to_string(AllocationAmount);
									std::string AllocationKind_str = std::to_string(AllocationKind);
									RtlCopyMemory(ELS.field.Fields[0].FieldName, "AllocationAmount", sizeof("AllocationAmount"));
									RtlCopyMemory(ELS.field.Fields[0].FieldValue, AllocationAmount_str.c_str(), AllocationAmount_str.length());
									RtlCopyMemory(ELS.field.Fields[1].FieldName, "AllocationKind", sizeof("AllocationKind"));
									RtlCopyMemory(ELS.field.Fields[1].FieldValue, AllocationKind_str.c_str(), AllocationKind_str.length());
									if (schema.event_version() == 1)
									{
										auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
										ELS.field.FieldCount = 3;
										std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
										RtlCopyMemory(ELS.field.Fields[2].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
										RtlCopyMemory(ELS.field.Fields[2].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
									}
								}
								else if (schema.event_version() == 2)
								{

									auto AllocationAmount = safe_parse<uint32_t>(parser, L"AllocationAmount");
									auto AllocationKind = safe_parse<uint32_t>(parser, L"AllocationKind");
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									auto AllocationAmount64 = safe_parse<uint64_t>(parser, L"AllocationAmount64");
									auto TypeID = safe_parse<uint64_t>(parser, L"TypeID"); // Pointer
									auto TypeName = EDR::Util::wchar_to_char ( (safe_parse<std::wstring>(parser, L"TypeName")).c_str() );
									auto HeapIndex = safe_parse<uint32_t>(parser, L"HeapIndex");
									ELS.field.FieldCount = 7;
									RtlCopyMemory(ELS.field.Fields[0].FieldName, "AllocationAmount", sizeof("AllocationAmount"));
									std::string s0 = std::to_string(AllocationAmount);
									RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS.field.Fields[1].FieldName, "AllocationKind", sizeof("AllocationKind"));
									std::string s1 = std::to_string(AllocationKind);
									RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
									RtlCopyMemory(ELS.field.Fields[2].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
									std::string s2 = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS.field.Fields[2].FieldValue, s2.c_str(), s2.length());
									RtlCopyMemory(ELS.field.Fields[3].FieldName, "AllocationAmount64", sizeof("AllocationAmount64"));
									std::string s3 = std::to_string(AllocationAmount64);
									RtlCopyMemory(ELS.field.Fields[3].FieldValue, s3.c_str(), s3.length());
									RtlCopyMemory(ELS.field.Fields[4].FieldName, "TypeID", sizeof("TypeID"));
									std::string s4 = std::to_string(TypeID);
									RtlCopyMemory(ELS.field.Fields[4].FieldValue, s4.c_str(), s4.length());
									RtlCopyMemory(ELS.field.Fields[5].FieldName, "TypeName", sizeof("TypeName"));
									RtlCopyMemory(ELS.field.Fields[5].FieldValue, TypeName.c_str(), TypeName.length());
									RtlCopyMemory(ELS.field.Fields[6].FieldName, "HeapIndex", sizeof("HeapIndex"));
									std::string s6 = std::to_string(HeapIndex);
									RtlCopyMemory(ELS.field.Fields[6].FieldValue, s6.c_str(), s6.length());
								}
								else if (schema.event_version() == 3)
								{
									auto AllocationAmount = safe_parse<uint32_t>(parser, L"AllocationAmount");
									auto AllocationKind = safe_parse<uint32_t>(parser, L"AllocationKind");
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									auto AllocationAmount64 = safe_parse<uint64_t>(parser, L"AllocationAmount64");
									auto TypeID = safe_parse<uint64_t>(parser, L"TypeID");
									auto TypeName = EDR::Util::wchar_to_char((safe_parse<std::wstring>(parser, L"TypeName")).c_str());
									auto HeapIndex = safe_parse<uint32_t>(parser, L"HeapIndex");
									auto Address = safe_parse<uint64_t>(parser, L"Address");
									ELS.field.FieldCount = 8;
									RtlCopyMemory(ELS.field.Fields[0].FieldName, "AllocationAmount", sizeof("AllocationAmount"));
									std::string s0 = std::to_string(AllocationAmount);
									RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS.field.Fields[1].FieldName, "AllocationKind", sizeof("AllocationKind"));
									std::string s1 = std::to_string(AllocationKind);
									RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
									RtlCopyMemory(ELS.field.Fields[2].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
									std::string s2 = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS.field.Fields[2].FieldValue, s2.c_str(), s2.length());
									RtlCopyMemory(ELS.field.Fields[3].FieldName, "AllocationAmount64", sizeof("AllocationAmount64"));
									std::string s3 = std::to_string(AllocationAmount64);
									RtlCopyMemory(ELS.field.Fields[3].FieldValue, s3.c_str(), s3.length());
									RtlCopyMemory(ELS.field.Fields[4].FieldName, "TypeID", sizeof("TypeID"));
									std::string s4 = std::to_string(TypeID);
									RtlCopyMemory(ELS.field.Fields[4].FieldValue, s4.c_str(), s4.length());
									RtlCopyMemory(ELS.field.Fields[5].FieldName, "TypeName", sizeof("TypeName"));
									RtlCopyMemory(ELS.field.Fields[5].FieldValue, TypeName.c_str(), TypeName.length());
									RtlCopyMemory(ELS.field.Fields[6].FieldName, "HeapIndex", sizeof("HeapIndex"));
									std::string s6 = std::to_string(HeapIndex);
									RtlCopyMemory(ELS.field.Fields[6].FieldValue, s6.c_str(), s6.length());
									RtlCopyMemory(ELS.field.Fields[7].FieldName, "Address", sizeof("Address"));
									std::string s7 = std::to_string(Address);
									RtlCopyMemory(ELS.field.Fields[7].FieldValue, s7.c_str(), s7.length());
								}
								break;
							}
							case 11:
							case 12:
							{
								if (schema.event_version() == 1)
								{
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS.field.FieldCount = 1;
									std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS.field.Fields[0].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
									RtlCopyMemory(ELS.field.Fields[0].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								}
								break;
							}
							case 13:
							{
								if (schema.event_version() == 0)
								{
									auto Count = safe_parse<uint32_t>(parser, L"Count");
									ELS.field.FieldCount = 1;
									std::string Count_str = std::to_string(Count);
									RtlCopyMemory(ELS.field.Fields[0].FieldName, "Count", sizeof("Count"));
									RtlCopyMemory(ELS.field.Fields[0].FieldValue, Count_str.c_str(), Count_str.length());
								}
								else if (schema.event_version() == 1)
								{
									auto Count = safe_parse<uint32_t>(parser, L"Count");
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS.field.FieldCount = 2;
									std::string Count_str = std::to_string(Count);
									std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS.field.Fields[0].FieldName, "Count", sizeof("Count"));
									RtlCopyMemory(ELS.field.Fields[0].FieldValue, Count_str.c_str(), Count_str.length());
									RtlCopyMemory(ELS.field.Fields[1].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
									RtlCopyMemory(ELS.field.Fields[1].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								}
								break;
							}
							case 14:
							{
								if (schema.event_version() == 1)
								{
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS.field.FieldCount = 1;
									std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS.field.Fields[0].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
									RtlCopyMemory(ELS.field.Fields[0].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								}
								break;
							}
							case 15:
							case 36:
							case 37:
							{
								auto Count = safe_parse<uint32_t>(parser, L"Count");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS.field.FieldCount = 2;
								std::string Count_str = std::to_string(Count);
								std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "Count", sizeof("Count"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, Count_str.c_str(), Count_str.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								break;
							}
							case 16:
							case 17:
							case 18:
							case 19:
							case 21:
							case 22:
							{
								auto Index = safe_parse<uint32_t>(parser, L"Index");
								auto Count = safe_parse<uint32_t>(parser, L"Count");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS.field.FieldCount = 3;
								std::string Index_str = std::to_string(Index);
								std::string Count_str = std::to_string(Count);
								std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "Index", sizeof("Index"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, Index_str.c_str(), Index_str.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "Count", sizeof("Count"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, Count_str.c_str(), Count_str.length());
								RtlCopyMemory(ELS.field.Fields[2].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[2].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								break;
							}
							case 20:
							case 32:
							{
								auto Address = safe_parse<uint64_t>(parser, L"Address");
								auto TypeID = safe_parse<uint64_t>(parser, L"TypeID");
								auto ObjectCountForTypeSample = safe_parse<uint32_t>(parser, L"ObjectCountForTypeSample");
								auto TotalSizeForTypeSample = safe_parse<uint64_t>(parser, L"TotalSizeForTypeSample");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS.field.FieldCount = 5;
								std::string s0 = std::to_string(Address);
								std::string s1 = std::to_string(TypeID);
								std::string s2 = std::to_string(ObjectCountForTypeSample);
								std::string s3 = std::to_string(TotalSizeForTypeSample);
								std::string s4 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "Address", sizeof("Address"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "TypeID", sizeof("TypeID"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS.field.Fields[2].FieldName, "ObjectCountForTypeSample", sizeof("ObjectCountForTypeSample"));
								RtlCopyMemory(ELS.field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS.field.Fields[3].FieldName, "TotalSizeForTypeSample", sizeof("TotalSizeForTypeSample"));
								RtlCopyMemory(ELS.field.Fields[3].FieldValue, s3.c_str(), s3.length());
								RtlCopyMemory(ELS.field.Fields[4].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[4].FieldValue, s4.c_str(), s4.length());
								break;
							}
							case 23:
							{
								auto Generation = safe_parse<uint8_t>(parser, L"Generation");
								auto RangeStart = safe_parse<uint64_t>(parser, L"RangeStart");
								auto RangeUsedLength = safe_parse<uint64_t>(parser, L"RangeUsedLength");
								auto RangeReservedLength = safe_parse<uint64_t>(parser, L"RangeReservedLength");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS.field.FieldCount = 5;
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "Generation", sizeof("Generation"));
								std::string s0 = std::to_string(Generation);
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "RangeStart", sizeof("RangeStart"));
								std::string s1 = std::to_string(RangeStart);
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS.field.Fields[2].FieldName, "RangeUsedLength", sizeof("RangeUsedLength"));
								std::string s2 = std::to_string(RangeUsedLength);
								RtlCopyMemory(ELS.field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS.field.Fields[3].FieldName, "RangeReservedLength", sizeof("RangeReservedLength"));
								std::string s3 = std::to_string(RangeReservedLength);
								RtlCopyMemory(ELS.field.Fields[3].FieldValue, s3.c_str(), s3.length());
								RtlCopyMemory(ELS.field.Fields[4].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								std::string s4 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[4].FieldValue, s4.c_str(), s4.length());
								break;
							}
							case 25:
							case 26:
							case 27:
							case 28:
							{
								auto HeapNum = safe_parse<uint32_t>(parser, L"HeapNum");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS.field.FieldCount = 2;
								std::string HeapNum_str = std::to_string(HeapNum);
								std::string ClrInstanceID_str = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "HeapNum", sizeof("HeapNum"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, HeapNum_str.c_str(), HeapNum_str.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, ClrInstanceID_str.c_str(), ClrInstanceID_str.length());
								break;
							}
							case 29:
							{
								auto TypeID = safe_parse<uint64_t>(parser, L"TypeID");
								auto ObjectID = safe_parse<uint64_t>(parser, L"ObjectID");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS.field.FieldCount = 3;
								std::string s0 = std::to_string(TypeID);
								std::string s1 = std::to_string(ObjectID);
								std::string s2 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "TypeID", sizeof("TypeID"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "ObjectID", sizeof("ObjectID"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS.field.Fields[2].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[2].FieldValue, s2.c_str(), s2.length());
								break;
							}
							case 30:
							{
								auto HandleID = safe_parse<uint64_t>(parser, L"HandleID");
								auto ObjectID = safe_parse<uint64_t>(parser, L"ObjectID");
								auto Kind = safe_parse<uint32_t>(parser, L"Kind");
								auto Generation = safe_parse<uint32_t>(parser, L"Generation");
								auto AppDomainID = safe_parse<uint64_t>(parser, L"AppDomainID");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS.field.FieldCount = 6;
								std::string s0 = std::to_string(HandleID);
								std::string s1 = std::to_string(ObjectID);
								std::string s2 = std::to_string(Kind);
								std::string s3 = std::to_string(Generation);
								std::string s4 = std::to_string(AppDomainID);
								std::string s5 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "HandleID", sizeof("HandleID"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "ObjectID", sizeof("ObjectID"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS.field.Fields[2].FieldName, "Kind", sizeof("Kind"));
								RtlCopyMemory(ELS.field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS.field.Fields[3].FieldName, "Generation", sizeof("Generation"));
								RtlCopyMemory(ELS.field.Fields[3].FieldValue, s3.c_str(), s3.length());
								RtlCopyMemory(ELS.field.Fields[4].FieldName, "AppDomainID", sizeof("AppDomainID"));
								RtlCopyMemory(ELS.field.Fields[4].FieldValue, s4.c_str(), s4.length());
								RtlCopyMemory(ELS.field.Fields[5].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[5].FieldValue, s5.c_str(), s5.length());
								break;
							}
							case 31:
							{
								auto HandleID = safe_parse<uint64_t>(parser, L"HandleID");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS.field.FieldCount = 2;
								std::string s0 = std::to_string(HandleID);
								std::string s1 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "HandleID", sizeof("HandleID"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								break;
							}
							case 33:
							{
								auto HandleID = safe_parse<uint64_t>(parser, L"HandleID");
								auto ObjectID = safe_parse<uint64_t>(parser, L"ObjectID");
								auto ObjectSize = safe_parse<uint64_t>(parser, L"ObjectSize");
								auto TypeName = EDR::Util::wchar_to_char( (safe_parse<std::wstring>(parser, L"TypeName")).c_str() );
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS.field.FieldCount = 5;
								std::string s0 = std::to_string(HandleID);
								std::string s1 = std::to_string(ObjectID);
								std::string s2 = std::to_string(ObjectSize);
								std::string s4 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "HandleID", sizeof("HandleID"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "ObjectID", sizeof("ObjectID"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS.field.Fields[2].FieldName, "ObjectSize", sizeof("ObjectSize"));
								RtlCopyMemory(ELS.field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS.field.Fields[3].FieldName, "TypeName", sizeof("TypeName"));
								RtlCopyMemory(ELS.field.Fields[3].FieldValue, TypeName.c_str(), TypeName.length());
								RtlCopyMemory(ELS.field.Fields[4].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[4].FieldValue, s4.c_str(), s4.length());
								break;
							}
							case 35:
							{
								auto Reason = safe_parse<uint32_t>(parser, L"Reason");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS.field.FieldCount = 2;
								std::string s0 = std::to_string(Reason);
								std::string s1 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "Reason", sizeof("Reason"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								break;
							}
							case 38:
							{
								auto Count = safe_parse<uint32_t>(parser, L"Count");
								auto AppDomainID = safe_parse<uint64_t>(parser, L"AppDomainID");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS.field.FieldCount = 3;
								std::string s0 = std::to_string(Count);
								std::string s1 = std::to_string(AppDomainID);
								std::string s2 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "Count", sizeof("Count"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "AppDomainID", sizeof("AppDomainID"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS.field.Fields[2].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[2].FieldValue, s2.c_str(), s2.length());
								break;
							}
							case 39:
							{
								auto Name = EDR::Util::wchar_to_char( (safe_parse<std::wstring>(parser, L"Name")).c_str() );
								auto DataSize = safe_parse<uint32_t>(parser, L"DataSize");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS.field.FieldCount = 3;
								std::string s1 = std::to_string(DataSize);
								std::string s2 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "Name", sizeof("Name"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, Name.c_str(), Name.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "DataSize", sizeof("DataSize"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS.field.Fields[2].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[2].FieldValue, s2.c_str(), s2.length());
								break;
							}
							case 40:
							case 41:
							case 42:
							case 43:
							{
								auto WorkerThreadCount = safe_parse<uint32_t>(parser, L"WorkerThreadCount");
								auto RetiredWorkerThreads = safe_parse<uint32_t>(parser, L"RetiredWorkerThreads");
								ELS.field.FieldCount = 2;
								std::string s0 = std::to_string(WorkerThreadCount);
								std::string s1 = std::to_string(RetiredWorkerThreads);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "WorkerThreadCount", sizeof("WorkerThreadCount"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "RetiredWorkerThreads", sizeof("RetiredWorkerThreads"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								break;
							}
							case 44:
							case 45:
							case 46:
							case 47:
							{
								auto IOThreadCount = safe_parse<uint32_t>(parser, L"IOThreadCount");
								auto RetiredIOThreads = safe_parse<uint32_t>(parser, L"RetiredIOThreads");
								ELS.field.FieldCount = 2;
								std::string s0 = std::to_string(IOThreadCount);
								std::string s1 = std::to_string(RetiredIOThreads);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "IOThreadCount", sizeof("IOThreadCount"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "RetiredIOThreads", sizeof("RetiredIOThreads"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								if (schema.event_version() == 1)
								{
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS.field.FieldCount = 3;
									std::string s2 = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS.field.Fields[2].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
									RtlCopyMemory(ELS.field.Fields[2].FieldValue, s2.c_str(), s2.length());
								}
								break;
							}
							case 48:
							case 49:
							{
								auto ClrThreadID = safe_parse<uint32_t>(parser, L"ClrThreadID");
								auto CpuUtilization = safe_parse<uint32_t>(parser, L"CpuUtilization");
								ELS.field.FieldCount = 2;
								std::string s0 = std::to_string(ClrThreadID);
								std::string s1 = std::to_string(CpuUtilization);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "ClrThreadID", sizeof("ClrThreadID"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "CpuUtilization", sizeof("CpuUtilization"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								break;
							}
							case 50:
							case 51:
							case 52:
							case 53:
							case 57:
							{
								auto ActiveWorkerThreadCount = safe_parse<uint32_t>(parser, L"ActiveWorkerThreadCount");
								auto RetiredWorkerThreadCount = safe_parse<uint32_t>(parser, L"RetiredWorkerThreadCount");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS.field.FieldCount = 3;
								std::string s0 = std::to_string(ActiveWorkerThreadCount);
								std::string s1 = std::to_string(RetiredWorkerThreadCount);
								std::string s2 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "ActiveWorkerThreadCount", sizeof("ActiveWorkerThreadCount"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "RetiredWorkerThreadCount", sizeof("RetiredWorkerThreadCount"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS.field.Fields[2].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[2].FieldValue, s2.c_str(), s2.length());
								break;
							}
							case 54:
							{
								auto Throughput = safe_parse<double>(parser, L"Throughput");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS.field.FieldCount = 2;
								std::string s0 = std::to_string(Throughput);
								std::string s1 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "Throughput", sizeof("Throughput"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								break;
							}
							case 55:
							{
								auto AverageThroughput = safe_parse<double>(parser, L"AverageThroughput");
								auto NewWorkerThreadCount = safe_parse<uint32_t>(parser, L"NewWorkerThreadCount");
								auto Reason = safe_parse<uint32_t>(parser, L"Reason");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS.field.FieldCount = 4;
								std::string s0 = std::to_string(AverageThroughput);
								std::string s1 = std::to_string(NewWorkerThreadCount);
								std::string s2 = std::to_string(Reason);
								std::string s3 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "AverageThroughput", sizeof("AverageThroughput"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "NewWorkerThreadCount", sizeof("NewWorkerThreadCount"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS.field.Fields[2].FieldName, "Reason", sizeof("Reason"));
								RtlCopyMemory(ELS.field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS.field.Fields[3].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[3].FieldValue, s3.c_str(), s3.length());
								break;
							}
							case 56:
							{
								field_idx = 0;
								auto Duration = safe_parse<double>(parser, L"Duration");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "Duration", sizeof("Duration"));
								std::string s0 = std::to_string(Duration);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s0.c_str(), s0.length());

								auto Throughput = safe_parse<double>(parser, L"Throughput");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "Throughput", sizeof("Throughput"));
								std::string s1 = std::to_string(Throughput);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s1.c_str(), s1.length());

								auto ThreadWave = safe_parse<double>(parser, L"ThreadWave");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ThreadWave", sizeof("ThreadWave"));
								std::string s2 = std::to_string(ThreadWave);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s2.c_str(), s2.length());

								auto ThroughputWave = safe_parse<double>(parser, L"ThroughputWave");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ThroughputWave", sizeof("ThroughputWave"));
								std::string s3 = std::to_string(ThroughputWave);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s3.c_str(), s3.length());

								auto ThroughputErrorEstimate = safe_parse<double>(parser, L"ThroughputErrorEstimate");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ThroughputErrorEstimate", sizeof("ThroughputErrorEstimate"));
								std::string s4 = std::to_string(ThroughputErrorEstimate);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s4.c_str(), s4.length());

								auto AverageThroughputErrorEstimate = safe_parse<double>(parser, L"AverageThroughputErrorEstimate");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "AverageThroughputErrorEstimate", sizeof("AverageThroughputErrorEstimate"));
								std::string s5 = std::to_string(AverageThroughputErrorEstimate);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s5.c_str(), s5.length());

								auto ThroughputRatio = safe_parse<double>(parser, L"ThroughputRatio");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ThroughputRatio", sizeof("ThroughputRatio"));
								std::string s6 = std::to_string(ThroughputRatio);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s6.c_str(), s6.length());

								auto Confidence = safe_parse<double>(parser, L"Confidence");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "Confidence", sizeof("Confidence"));
								std::string s7 = std::to_string(Confidence);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s7.c_str(), s7.length());

								auto NewControlSetting = safe_parse<double>(parser, L"NewControlSetting");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "NewControlSetting", sizeof("NewControlSetting"));
								std::string s8 = std::to_string(NewControlSetting);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s8.c_str(), s8.length());

								auto NewThreadWaveMagnitude = safe_parse<uint16_t>(parser, L"NewThreadWaveMagnitude");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "NewThreadWaveMagnitude", sizeof("NewThreadWaveMagnitude"));
								std::string s9 = std::to_string(NewThreadWaveMagnitude);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s9.c_str(), s9.length());

								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								std::string s10 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s10.c_str(), s10.length());

								ELS.field.FieldCount = field_idx;
								break;
							}
							case 60:
							{
								auto Count = safe_parse<uint32_t>(parser, L"Count");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS.field.FieldCount = 2;
								std::string s0 = std::to_string(Count);
								std::string s1 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "Count", sizeof("Count"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								break;
							}
							case 61:
							case 62:
							{
								auto WorkID = safe_parse<uint64_t>(parser, L"WorkID");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS.field.FieldCount = 2;
								std::string s0 = std::to_string(WorkID);
								std::string s1 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "WorkID", sizeof("WorkID"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								break;
							}
							case 63:
							{
								auto NativeOverlapped = safe_parse<uint64_t>(parser, L"NativeOverlapped");
								auto Overlapped = safe_parse<uint64_t>(parser, L"Overlapped");
								auto MultiDequeues = safe_parse<bool>(parser, L"MultiDequeues");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS.field.FieldCount = 4;
								std::string s0 = std::to_string(NativeOverlapped);
								std::string s1 = std::to_string(Overlapped);
								std::string s2 = MultiDequeues ? "true" : "false";
								std::string s3 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "NativeOverlapped", sizeof("NativeOverlapped"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "Overlapped", sizeof("Overlapped"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS.field.Fields[2].FieldName, "MultiDequeues", sizeof("MultiDequeues"));
								RtlCopyMemory(ELS.field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS.field.Fields[3].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[3].FieldValue, s3.c_str(), s3.length());
								break;
							}
							case 64:
							case 65:
							{
								auto NativeOverlapped = safe_parse<uint64_t>(parser, L"NativeOverlapped");
								auto Overlapped = safe_parse<uint64_t>(parser, L"Overlapped");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS.field.FieldCount = 3;
								std::string s0 = std::to_string(NativeOverlapped);
								std::string s1 = std::to_string(Overlapped);
								std::string s2 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "NativeOverlapped", sizeof("NativeOverlapped"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "Overlapped", sizeof("Overlapped"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS.field.Fields[2].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[2].FieldValue, s2.c_str(), s2.length());
								break;
							}
							case 70:
							case 71:
							{
								auto ID = safe_parse<uint64_t>(parser, L"ID");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS.field.FieldCount = 2;
								std::string s0 = std::to_string(ID);
								std::string s1 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "ID", sizeof("ID"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								break;
							}
							case 80:
							{
								if (schema.event_version() == 1)
								{
									auto ExceptionType = EDR::Util::wchar_to_char( (safe_parse<std::wstring>(parser, L"ExceptionType")).c_str() );
									auto ExceptionMessage = EDR::Util::wchar_to_char( (safe_parse<std::wstring>(parser, L"ExceptionMessage")).c_str() );
									auto ExceptionEIP = safe_parse<uint64_t>(parser, L"ExceptionEIP");
									auto ExceptionHRESULT = safe_parse<uint32_t>(parser, L"ExceptionHRESULT");
									auto ExceptionFlags = safe_parse<uint16_t>(parser, L"ExceptionFlags");
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS.field.FieldCount = 6;
									std::string s2 = std::to_string(ExceptionEIP);
									std::string s3 = std::to_string(ExceptionHRESULT);
									std::string s4 = std::to_string(ExceptionFlags);
									std::string s5 = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS.field.Fields[0].FieldName, "ExceptionType", sizeof("ExceptionType"));
									RtlCopyMemory(ELS.field.Fields[0].FieldValue, ExceptionType.c_str(), ExceptionType.length());
									RtlCopyMemory(ELS.field.Fields[1].FieldName, "ExceptionMessage", sizeof("ExceptionMessage"));
									RtlCopyMemory(ELS.field.Fields[1].FieldValue, ExceptionMessage.c_str(), ExceptionMessage.length());
									RtlCopyMemory(ELS.field.Fields[2].FieldName, "ExceptionEIP", sizeof("ExceptionEIP"));
									RtlCopyMemory(ELS.field.Fields[2].FieldValue, s2.c_str(), s2.length());
									RtlCopyMemory(ELS.field.Fields[3].FieldName, "ExceptionHRESULT", sizeof("ExceptionHRESULT"));
									RtlCopyMemory(ELS.field.Fields[3].FieldValue, s3.c_str(), s3.length());
									RtlCopyMemory(ELS.field.Fields[4].FieldName, "ExceptionFlags", sizeof("ExceptionFlags"));
									RtlCopyMemory(ELS.field.Fields[4].FieldValue, s4.c_str(), s4.length());
									RtlCopyMemory(ELS.field.Fields[5].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
									RtlCopyMemory(ELS.field.Fields[5].FieldValue, s5.c_str(), s5.length());
								}
								break;
							}
							case 81:
							{
								if (schema.event_version() == 1)
								{
									auto ContentionFlags = safe_parse<uint8_t>(parser, L"ContentionFlags");
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									ELS.field.FieldCount = 2;
									std::string s0 = std::to_string(ContentionFlags);
									std::string s1 = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS.field.Fields[0].FieldName, "ContentionFlags", sizeof("ContentionFlags"));
									RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS.field.Fields[1].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
									RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								}
								break;
							}
							case 82:
							{
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								auto FrameCount = safe_parse<uint32_t>(parser, L"FrameCount");
								auto Stack = safe_parse<uint64_t>(parser, L"Stack");
								ELS.field.FieldCount = 3;
								std::string s0 = std::to_string(ClrInstanceID);
								std::string s1 = std::to_string(FrameCount);
								std::string s2 = std::to_string(Stack);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "FrameCount", sizeof("FrameCount"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS.field.Fields[2].FieldName, "Stack", sizeof("Stack"));
								RtlCopyMemory(ELS.field.Fields[2].FieldValue, s2.c_str(), s2.length());
								break;
							}
							case 83:
							{
								auto AppDomainID = safe_parse<uint64_t>(parser, L"AppDomainID");
								auto Allocated = safe_parse<uint64_t>(parser, L"Allocated");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS.field.FieldCount = 3;
								std::string s0 = std::to_string(AppDomainID);
								std::string s1 = std::to_string(Allocated);
								std::string s2 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "AppDomainID", sizeof("AppDomainID"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "Allocated", sizeof("Allocated"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS.field.Fields[2].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[2].FieldValue, s2.c_str(), s2.length());
								break;
							}
							case 84:
							{
								auto AppDomainID = safe_parse<uint64_t>(parser, L"AppDomainID");
								auto Survived = safe_parse<uint64_t>(parser, L"Survived");
								auto ProcessSurvived = safe_parse<uint64_t>(parser, L"ProcessSurvived");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS.field.FieldCount = 4;
								std::string s0 = std::to_string(AppDomainID);
								std::string s1 = std::to_string(Survived);
								std::string s2 = std::to_string(ProcessSurvived);
								std::string s3 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "AppDomainID", sizeof("AppDomainID"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "Survived", sizeof("Survived"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS.field.Fields[2].FieldName, "ProcessSurvived", sizeof("ProcessSurvived"));
								RtlCopyMemory(ELS.field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS.field.Fields[3].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[3].FieldValue, s3.c_str(), s3.length());
								break;
							}
							case 85:
							{
								auto ManagedThreadID = safe_parse<uint64_t>(parser, L"ManagedThreadID");
								auto AppDomainID = safe_parse<uint64_t>(parser, L"AppDomainID");
								auto Flags = safe_parse<uint32_t>(parser, L"Flags");
								auto ManagedThreadIndex = safe_parse<uint32_t>(parser, L"ManagedThreadIndex");
								auto OSThreadID = safe_parse<uint32_t>(parser, L"OSThreadID");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS.field.FieldCount = 6;
								std::string s0 = std::to_string(ManagedThreadID);
								std::string s1 = std::to_string(AppDomainID);
								std::string s2 = std::to_string(Flags);
								std::string s3 = std::to_string(ManagedThreadIndex);
								std::string s4 = std::to_string(OSThreadID);
								std::string s5 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "ManagedThreadID", sizeof("ManagedThreadID"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "AppDomainID", sizeof("AppDomainID"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS.field.Fields[2].FieldName, "Flags", sizeof("Flags"));
								RtlCopyMemory(ELS.field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS.field.Fields[3].FieldName, "ManagedThreadIndex", sizeof("ManagedThreadIndex"));
								RtlCopyMemory(ELS.field.Fields[3].FieldValue, s3.c_str(), s3.length());
								RtlCopyMemory(ELS.field.Fields[4].FieldName, "OSThreadID", sizeof("OSThreadID"));
								RtlCopyMemory(ELS.field.Fields[4].FieldValue, s4.c_str(), s4.length());
								RtlCopyMemory(ELS.field.Fields[5].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[5].FieldValue, s5.c_str(), s5.length());
								break;
							}
							case 86:
							case 87:
							{
								auto ManagedThreadID = safe_parse<uint64_t>(parser, L"ManagedThreadID");
								auto AppDomainID = safe_parse<uint64_t>(parser, L"AppDomainID");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS.field.FieldCount = 3;
								std::string s0 = std::to_string(ManagedThreadID);
								std::string s1 = std::to_string(AppDomainID);
								std::string s2 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "ManagedThreadID", sizeof("ManagedThreadID"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "AppDomainID", sizeof("AppDomainID"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS.field.Fields[2].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[2].FieldValue, s2.c_str(), s2.length());
								break;
							}
							case 88:
							{
								field_idx = 0;
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								std::string s0 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s0.c_str(), s0.length());

								auto ModuleID = safe_parse<uint64_t>(parser, L"ModuleID");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ModuleID", sizeof("ModuleID"));
								std::string s1 = std::to_string(ModuleID);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s1.c_str(), s1.length());

								auto StubMethodID = safe_parse<uint64_t>(parser, L"StubMethodID");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "StubMethodID", sizeof("StubMethodID"));
								std::string s2 = std::to_string(StubMethodID);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s2.c_str(), s2.length());

								auto StubFlags = safe_parse<uint32_t>(parser, L"StubFlags");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "StubFlags", sizeof("StubFlags"));
								std::string s3 = std::to_string(StubFlags);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s3.c_str(), s3.length());

								auto ManagedInteropMethodToken = safe_parse<uint32_t>(parser, L"ManagedInteropMethodToken");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ManagedInteropMethodToken", sizeof("ManagedInteropMethodToken"));
								std::string s4 = std::to_string(ManagedInteropMethodToken);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s4.c_str(), s4.length());

								auto ManagedInteropMethodNamespace = EDR::Util::wchar_to_char( (safe_parse<std::wstring>(parser, L"ManagedInteropMethodNamespace")).c_str() );
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ManagedInteropMethodNamespace", sizeof("ManagedInteropMethodNamespace"));
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, ManagedInteropMethodNamespace.c_str(), ManagedInteropMethodNamespace.length());

								auto ManagedInteropMethodName = EDR::Util::wchar_to_char( (safe_parse<std::wstring>(parser, L"ManagedInteropMethodName")).c_str() );
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ManagedInteropMethodName", sizeof("ManagedInteropMethodName"));
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, ManagedInteropMethodName.c_str(), ManagedInteropMethodName.length());

								auto ManagedInteropMethodSignature = EDR::Util::wchar_to_char( (safe_parse<std::wstring>(parser, L"ManagedInteropMethodSignature")).c_str() );
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ManagedInteropMethodSignature", sizeof("ManagedInteropMethodSignature"));
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, ManagedInteropMethodSignature.c_str(), ManagedInteropMethodSignature.length());

								ELS.field.FieldCount = field_idx;
								break;
							}
							case 89:
							{
								field_idx = 0;
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								std::string s0 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s0.c_str(), s0.length());

								auto ModuleID = safe_parse<uint64_t>(parser, L"ModuleID");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ModuleID", sizeof("ModuleID"));
								std::string s1 = std::to_string(ModuleID);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s1.c_str(), s1.length());

								auto StubMethodID = safe_parse<uint64_t>(parser, L"StubMethodID");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "StubMethodID", sizeof("StubMethodID"));
								std::string s2 = std::to_string(StubMethodID);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s2.c_str(), s2.length());

								auto ManagedInteropMethodToken = safe_parse<uint32_t>(parser, L"ManagedInteropMethodToken");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ManagedInteropMethodToken", sizeof("ManagedInteropMethodToken"));
								std::string s3 = std::to_string(ManagedInteropMethodToken);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s3.c_str(), s3.length());

								auto ManagedInteropMethodNamespace = EDR::Util::wchar_to_char( (safe_parse<std::wstring>(parser, L"ManagedInteropMethodNamespace")).c_str() );
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ManagedInteropMethodNamespace", sizeof("ManagedInteropMethodNamespace"));
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, ManagedInteropMethodNamespace.c_str(), ManagedInteropMethodNamespace.length());

								auto ManagedInteropMethodName = EDR::Util::wchar_to_char((safe_parse<std::wstring>(parser, L"ManagedInteropMethodName")).c_str() );
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ManagedInteropMethodName", sizeof("ManagedInteropMethodName"));
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, ManagedInteropMethodName.c_str(), ManagedInteropMethodName.length());

								auto ManagedInteropMethodSignature = EDR::Util::wchar_to_char((safe_parse<std::wstring>(parser, L"ManagedInteropMethodSignature")).c_str() );
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ManagedInteropMethodSignature", sizeof("ManagedInteropMethodSignature"));
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, ManagedInteropMethodSignature.c_str(), ManagedInteropMethodSignature.length());

								ELS.field.FieldCount = field_idx;
								break;
							}
							case 91:
							{
								auto ContentionFlags = safe_parse<uint8_t>(parser, L"ContentionFlags");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS.field.FieldCount = 2;
								std::string s0 = std::to_string(ContentionFlags);
								std::string s1 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "ContentionFlags", sizeof("ContentionFlags"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								break;
							}
							case 137:
							case 138:
							case 141:
							case 142:
							{
								if (schema.event_version() == 0 || schema.event_version() == 1 || schema.event_version() == 2)
								{
									auto MethodID = safe_parse<uint64_t>(parser, L"MethodID");
									auto ModuleID = safe_parse<uint64_t>(parser, L"ModuleID");
									auto MethodStartAddress = safe_parse<uint64_t>(parser, L"MethodStartAddress");
									auto MethodSize = safe_parse<uint32_t>(parser, L"MethodSize");
									auto MethodToken = safe_parse<uint32_t>(parser, L"MethodToken");
									auto MethodFlags = safe_parse<uint32_t>(parser, L"MethodFlags");
									field_idx = 6;
									std::string s0 = std::to_string(MethodID);
									std::string s1 = std::to_string(ModuleID);
									std::string s2 = std::to_string(MethodStartAddress);
									std::string s3 = std::to_string(MethodSize);
									std::string s4 = std::to_string(MethodToken);
									std::string s5 = std::to_string(MethodFlags);
									RtlCopyMemory(ELS.field.Fields[0].FieldName, "MethodID", sizeof("MethodID"));
									RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS.field.Fields[1].FieldName, "ModuleID", sizeof("ModuleID"));
									RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
									RtlCopyMemory(ELS.field.Fields[2].FieldName, "MethodStartAddress", sizeof("MethodStartAddress"));
									RtlCopyMemory(ELS.field.Fields[2].FieldValue, s2.c_str(), s2.length());
									RtlCopyMemory(ELS.field.Fields[3].FieldName, "MethodSize", sizeof("MethodSize"));
									RtlCopyMemory(ELS.field.Fields[3].FieldValue, s3.c_str(), s3.length());
									RtlCopyMemory(ELS.field.Fields[4].FieldName, "MethodToken", sizeof("MethodToken"));
									RtlCopyMemory(ELS.field.Fields[4].FieldValue, s4.c_str(), s4.length());
									RtlCopyMemory(ELS.field.Fields[5].FieldName, "MethodFlags", sizeof("MethodFlags"));
									RtlCopyMemory(ELS.field.Fields[5].FieldValue, s5.c_str(), s5.length());
									if (schema.event_version() >= 1)
									{
										auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
										std::string s6 = std::to_string(ClrInstanceID);
										RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
										RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s6.c_str(), s6.length());
									}
									if (schema.event_version() == 2)
									{
										auto ReJITID = safe_parse<uint64_t>(parser, L"ReJITID");
										std::string s7 = std::to_string(ReJITID);
										RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ReJITID", sizeof("ReJITID"));
										RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s7.c_str(), s7.length());
									}
									ELS.field.FieldCount = field_idx;
								}
								break;
							}
							case 139:
							case 140:
							case 143:
							case 144:
							{
								if (schema.event_version() == 0 || schema.event_version() == 1 || schema.event_version() == 2)
								{
									auto MethodID = safe_parse<uint64_t>(parser, L"MethodID");
									auto ModuleID = safe_parse<uint64_t>(parser, L"ModuleID");
									auto MethodStartAddress = safe_parse<uint64_t>(parser, L"MethodStartAddress");
									auto MethodSize = safe_parse<uint32_t>(parser, L"MethodSize");
									auto MethodToken = safe_parse<uint32_t>(parser, L"MethodToken");
									auto MethodFlags = safe_parse<uint32_t>(parser, L"MethodFlags");
									auto MethodNamespace = EDR::Util::wchar_to_char(safe_parse<std::wstring>(parser, L"MethodNamespace").c_str());
									auto MethodName = EDR::Util::wchar_to_char(safe_parse<std::wstring>(parser, L"MethodName").c_str());
									auto MethodSignature = EDR::Util::wchar_to_char(safe_parse<std::wstring>(parser, L"MethodSignature").c_str());
									field_idx = 9;
									std::string s0 = std::to_string(MethodID);
									std::string s1 = std::to_string(ModuleID);
									std::string s2 = std::to_string(MethodStartAddress);
									std::string s3 = std::to_string(MethodSize);
									std::string s4 = std::to_string(MethodToken);
									std::string s5 = std::to_string(MethodFlags);
									RtlCopyMemory(ELS.field.Fields[0].FieldName, "MethodID", sizeof("MethodID"));
									RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
									RtlCopyMemory(ELS.field.Fields[1].FieldName, "ModuleID", sizeof("ModuleID"));
									RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
									RtlCopyMemory(ELS.field.Fields[2].FieldName, "MethodStartAddress", sizeof("MethodStartAddress"));
									RtlCopyMemory(ELS.field.Fields[2].FieldValue, s2.c_str(), s2.length());
									RtlCopyMemory(ELS.field.Fields[3].FieldName, "MethodSize", sizeof("MethodSize"));
									RtlCopyMemory(ELS.field.Fields[3].FieldValue, s3.c_str(), s3.length());
									RtlCopyMemory(ELS.field.Fields[4].FieldName, "MethodToken", sizeof("MethodToken"));
									RtlCopyMemory(ELS.field.Fields[4].FieldValue, s4.c_str(), s4.length());
									RtlCopyMemory(ELS.field.Fields[5].FieldName, "MethodFlags", sizeof("MethodFlags"));
									RtlCopyMemory(ELS.field.Fields[5].FieldValue, s5.c_str(), s5.length());
									RtlCopyMemory(ELS.field.Fields[6].FieldName, "MethodNamespace", sizeof("MethodNamespace"));
									RtlCopyMemory(ELS.field.Fields[6].FieldValue, MethodNamespace.c_str(), MethodNamespace.length());
									RtlCopyMemory(ELS.field.Fields[7].FieldName, "MethodName", sizeof("MethodName"));
									RtlCopyMemory(ELS.field.Fields[7].FieldValue, MethodName.c_str(), MethodName.length());
									RtlCopyMemory(ELS.field.Fields[8].FieldName, "MethodSignature", sizeof("MethodSignature"));
									RtlCopyMemory(ELS.field.Fields[8].FieldValue, MethodSignature.c_str(), MethodSignature.length());
									if (schema.event_version() >= 1)
									{
										auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
										std::string s9 = std::to_string(ClrInstanceID);
										RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
										RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s9.c_str(), s9.length());
									}
									if (schema.event_version() == 2)
									{
										auto ReJITID = safe_parse<uint64_t>(parser, L"ReJITID");
										std::string s10 = std::to_string(ReJITID);
										RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ReJITID", sizeof("ReJITID"));
										RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s10.c_str(), s10.length());
									}
									ELS.field.FieldCount = field_idx;
								}
								break;
							}
							case 145:
							{
								auto MethodID = safe_parse<uint64_t>(parser, L"MethodID");
								auto ModuleID = safe_parse<uint64_t>(parser, L"ModuleID");
								auto MethodToken = safe_parse<uint32_t>(parser, L"MethodToken");
								auto MethodILSize = safe_parse<uint32_t>(parser, L"MethodILSize");
								auto MethodNamespace = EDR::Util::wchar_to_char(safe_parse<std::wstring>(parser, L"MethodNamespace").c_str());
								auto MethodName = EDR::Util::wchar_to_char(safe_parse<std::wstring>(parser, L"MethodName").c_str());
								auto MethodSignature = EDR::Util::wchar_to_char(safe_parse<std::wstring>(parser, L"MethodSignature").c_str());
								field_idx = 7;
								std::string s0 = std::to_string(MethodID);
								std::string s1 = std::to_string(ModuleID);
								std::string s2 = std::to_string(MethodToken);
								std::string s3 = std::to_string(MethodILSize);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "MethodID", sizeof("MethodID"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "ModuleID", sizeof("ModuleID"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS.field.Fields[2].FieldName, "MethodToken", sizeof("MethodToken"));
								RtlCopyMemory(ELS.field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS.field.Fields[3].FieldName, "MethodILSize", sizeof("MethodILSize"));
								RtlCopyMemory(ELS.field.Fields[3].FieldValue, s3.c_str(), s3.length());
								RtlCopyMemory(ELS.field.Fields[4].FieldName, "MethodNamespace", sizeof("MethodNamespace"));
								RtlCopyMemory(ELS.field.Fields[4].FieldValue, MethodNamespace.c_str(), MethodNamespace.length());
								RtlCopyMemory(ELS.field.Fields[5].FieldName, "MethodName", sizeof("MethodName"));
								RtlCopyMemory(ELS.field.Fields[5].FieldValue, MethodName.c_str(), MethodName.length());
								RtlCopyMemory(ELS.field.Fields[6].FieldName, "MethodSignature", sizeof("MethodSignature"));
								RtlCopyMemory(ELS.field.Fields[6].FieldValue, MethodSignature.c_str(), MethodSignature.length());
								if (schema.event_version() == 1)
								{
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									std::string s7 = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
									RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s7.c_str(), s7.length());
								}
								ELS.field.FieldCount = field_idx;
								break;
							}
							case 149:
							case 150:
							{
								auto ModuleID = safe_parse<uint64_t>(parser, L"ModuleID");
								auto AssemblyID = safe_parse<uint64_t>(parser, L"AssemblyID");
								auto ModuleFlags = safe_parse<uint32_t>(parser, L"ModuleFlags");
								auto ModuleILPath = EDR::Util::wchar_to_char(safe_parse<std::wstring>(parser, L"ModuleILPath").c_str());
								auto ModuleNativePath = EDR::Util::wchar_to_char(safe_parse<std::wstring>(parser, L"ModuleNativePath").c_str());
								ELS.field.FieldCount = 5;
								std::string s0 = std::to_string(ModuleID);
								std::string s1 = std::to_string(AssemblyID);
								std::string s2 = std::to_string(ModuleFlags);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "ModuleID", sizeof("ModuleID"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "AssemblyID", sizeof("AssemblyID"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS.field.Fields[2].FieldName, "ModuleFlags", sizeof("ModuleFlags"));
								RtlCopyMemory(ELS.field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS.field.Fields[3].FieldName, "ModuleILPath", sizeof("ModuleILPath"));
								RtlCopyMemory(ELS.field.Fields[3].FieldValue, ModuleILPath.c_str(), ModuleILPath.length());
								RtlCopyMemory(ELS.field.Fields[4].FieldName, "ModuleNativePath", sizeof("ModuleNativePath"));
								RtlCopyMemory(ELS.field.Fields[4].FieldValue, ModuleNativePath.c_str(), ModuleNativePath.length());
								break;
							}
							case 151:
							{
								auto ModuleID = safe_parse<uint64_t>(parser, L"ModuleID");
								auto AssemblyID = safe_parse<uint64_t>(parser, L"AssemblyID");
								auto AppDomainID = safe_parse<uint64_t>(parser, L"AppDomainID");
								auto ModuleFlags = safe_parse<uint32_t>(parser, L"ModuleFlags");
								auto ModuleILPath = EDR::Util::wchar_to_char(safe_parse<std::wstring>(parser, L"ModuleILPath").c_str());
								auto ModuleNativePath = EDR::Util::wchar_to_char(safe_parse<std::wstring>(parser, L"ModuleNativePath").c_str());
								field_idx = 6;
								std::string s0 = std::to_string(ModuleID);
								std::string s1 = std::to_string(AssemblyID);
								std::string s2 = std::to_string(AppDomainID);
								std::string s3 = std::to_string(ModuleFlags);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "ModuleID", sizeof("ModuleID"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "AssemblyID", sizeof("AssemblyID"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS.field.Fields[2].FieldName, "AppDomainID", sizeof("AppDomainID"));
								RtlCopyMemory(ELS.field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS.field.Fields[3].FieldName, "ModuleFlags", sizeof("ModuleFlags"));
								RtlCopyMemory(ELS.field.Fields[3].FieldValue, s3.c_str(), s3.length());
								RtlCopyMemory(ELS.field.Fields[4].FieldName, "ModuleILPath", sizeof("ModuleILPath"));
								RtlCopyMemory(ELS.field.Fields[4].FieldValue, ModuleILPath.c_str(), ModuleILPath.length());
								RtlCopyMemory(ELS.field.Fields[5].FieldName, "ModuleNativePath", sizeof("ModuleNativePath"));
								RtlCopyMemory(ELS.field.Fields[5].FieldValue, ModuleNativePath.c_str(), ModuleNativePath.length());
								if (schema.event_version() == 1)
								{
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									std::string s6 = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
									RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s6.c_str(), s6.length());
								}
								ELS.field.FieldCount = field_idx;
								break;
							}
							case 152:
							case 153:
							{
								auto ModuleID = safe_parse<uint64_t>(parser, L"ModuleID");
								auto AssemblyID = safe_parse<uint64_t>(parser, L"AssemblyID");
								auto ModuleFlags = safe_parse<uint32_t>(parser, L"ModuleFlags");
								auto ModuleILPath = EDR::Util::wchar_to_char(safe_parse<std::wstring>(parser, L"ModuleILPath").c_str());
								auto ModuleNativePath = EDR::Util::wchar_to_char(safe_parse<std::wstring>(parser, L"ModuleNativePath").c_str());
								field_idx = 5;
								std::string s0 = std::to_string(ModuleID);
								std::string s1 = std::to_string(AssemblyID);
								std::string s2 = std::to_string(ModuleFlags);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "ModuleID", sizeof("ModuleID"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "AssemblyID", sizeof("AssemblyID"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS.field.Fields[2].FieldName, "ModuleFlags", sizeof("ModuleFlags"));
								RtlCopyMemory(ELS.field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS.field.Fields[3].FieldName, "ModuleILPath", sizeof("ModuleILPath"));
								RtlCopyMemory(ELS.field.Fields[3].FieldValue, ModuleILPath.c_str(), ModuleILPath.length());
								RtlCopyMemory(ELS.field.Fields[4].FieldName, "ModuleNativePath", sizeof("ModuleNativePath"));
								RtlCopyMemory(ELS.field.Fields[4].FieldValue, ModuleNativePath.c_str(), ModuleNativePath.length());
								if (schema.event_version() >= 1)
								{
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									std::string s5 = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
									RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s5.c_str(), s5.length());
								}
								ELS.field.FieldCount = field_idx;
								break;
							}
							case 154:
							case 155:
							{
								auto AssemblyID = safe_parse<uint64_t>(parser, L"AssemblyID");
								auto AppDomainID = safe_parse<uint64_t>(parser, L"AppDomainID");
								auto AssemblyFlags = safe_parse<uint32_t>(parser, L"AssemblyFlags");
								auto FullyQualifiedAssemblyName = EDR::Util::wchar_to_char(safe_parse<std::wstring>(parser, L"FullyQualifiedAssemblyName").c_str());
								field_idx = 4;
								std::string s0 = std::to_string(AssemblyID);
								std::string s1 = std::to_string(AppDomainID);
								std::string s2 = std::to_string(AssemblyFlags);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "AssemblyID", sizeof("AssemblyID"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "AppDomainID", sizeof("AppDomainID"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS.field.Fields[2].FieldName, "AssemblyFlags", sizeof("AssemblyFlags"));
								RtlCopyMemory(ELS.field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS.field.Fields[3].FieldName, "FullyQualifiedAssemblyName", sizeof("FullyQualifiedAssemblyName"));
								RtlCopyMemory(ELS.field.Fields[3].FieldValue, FullyQualifiedAssemblyName.c_str(), FullyQualifiedAssemblyName.length());
								if (schema.event_version() == 1)
								{
									auto BindingID = safe_parse<uint64_t>(parser, L"BindingID");
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									std::string s4 = std::to_string(BindingID);
									std::string s5 = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "BindingID", sizeof("BindingID"));
									RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s4.c_str(), s4.length());
									RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
									RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s5.c_str(), s5.length());
								}
								ELS.field.FieldCount = field_idx;
								break;
							}
							case 156:
							case 157:
							{
								auto AppDomainID = safe_parse<uint64_t>(parser, L"AppDomainID");
								auto AppDomainFlags = safe_parse<uint32_t>(parser, L"AppDomainFlags");
								auto AppDomainName = EDR::Util::wchar_to_char(safe_parse<std::wstring>(parser, L"AppDomainName").c_str());
								field_idx = 3;
								std::string s0 = std::to_string(AppDomainID);
								std::string s1 = std::to_string(AppDomainFlags);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "AppDomainID", sizeof("AppDomainID"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "AppDomainFlags", sizeof("AppDomainFlags"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS.field.Fields[2].FieldName, "AppDomainName", sizeof("AppDomainName"));
								RtlCopyMemory(ELS.field.Fields[2].FieldValue, AppDomainName.c_str(), AppDomainName.length());
								if (schema.event_version() == 1)
								{
									auto AppDomainIndex = safe_parse<uint32_t>(parser, L"AppDomainIndex");
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									std::string s3 = std::to_string(AppDomainIndex);
									std::string s4 = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "AppDomainIndex", sizeof("AppDomainIndex"));
									RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s3.c_str(), s3.length());
									RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
									RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s4.c_str(), s4.length());
								}
								ELS.field.FieldCount = field_idx;
								break;
							}
							case 158:
							{
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								auto ModuleID = safe_parse<uint64_t>(parser, L"ModuleID");
								auto RangeBegin = safe_parse<uint32_t>(parser, L"RangeBegin");
								auto RangeSize = safe_parse<uint32_t>(parser, L"RangeSize");
								auto RangeType = safe_parse<uint8_t>(parser, L"RangeType");
								ELS.field.FieldCount = 5;
								std::string s0 = std::to_string(ClrInstanceID);
								std::string s1 = std::to_string(ModuleID);
								std::string s2 = std::to_string(RangeBegin);
								std::string s3 = std::to_string(RangeSize);
								std::string s4 = std::to_string(RangeType);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "ModuleID", sizeof("ModuleID"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS.field.Fields[2].FieldName, "RangeBegin", sizeof("RangeBegin"));
								RtlCopyMemory(ELS.field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS.field.Fields[3].FieldName, "RangeSize", sizeof("RangeSize"));
								RtlCopyMemory(ELS.field.Fields[3].FieldValue, s3.c_str(), s3.length());
								RtlCopyMemory(ELS.field.Fields[4].FieldName, "RangeType", sizeof("RangeType"));
								RtlCopyMemory(ELS.field.Fields[4].FieldValue, s4.c_str(), s4.length());
								break;
							}
							case 181:
							case 182:
							{
								auto VerificationFlags = safe_parse<uint32_t>(parser, L"VerificationFlags");
								auto ErrorCode = safe_parse<uint32_t>(parser, L"ErrorCode");
								auto FullyQualifiedAssemblyName = EDR::Util::wchar_to_char(safe_parse<std::wstring>(parser, L"FullyQualifiedAssemblyName").c_str());
								field_idx = 3;
								std::string s0 = std::to_string(VerificationFlags);
								std::string s1 = std::to_string(ErrorCode);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "VerificationFlags", sizeof("VerificationFlags"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "ErrorCode", sizeof("ErrorCode"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS.field.Fields[2].FieldName, "FullyQualifiedAssemblyName", sizeof("FullyQualifiedAssemblyName"));
								RtlCopyMemory(ELS.field.Fields[2].FieldValue, FullyQualifiedAssemblyName.c_str(), FullyQualifiedAssemblyName.length());
								if (schema.event_version() == 1)
								{
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									std::string s3 = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
									RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s3.c_str(), s3.length());
								}
								ELS.field.FieldCount = field_idx;
								break;
							}
							case 183:
							case 184:
							{
								auto VerificationFlags = safe_parse<uint32_t>(parser, L"VerificationFlags");
								auto ErrorCode = safe_parse<uint32_t>(parser, L"ErrorCode");
								auto ModulePath = EDR::Util::wchar_to_char(safe_parse<std::wstring>(parser, L"ModulePath").c_str());
								field_idx = 3;
								std::string s0 = std::to_string(VerificationFlags);
								std::string s1 = std::to_string(ErrorCode);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "VerificationFlags", sizeof("VerificationFlags"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "ErrorCode", sizeof("ErrorCode"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS.field.Fields[2].FieldName, "ModulePath", sizeof("ModulePath"));
								RtlCopyMemory(ELS.field.Fields[2].FieldValue, ModulePath.c_str(), ModulePath.length());
								if (schema.event_version() == 1)
								{
									auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
									std::string s3 = std::to_string(ClrInstanceID);
									RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
									RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s3.c_str(), s3.length());
								}
								ELS.field.FieldCount = field_idx;
								break;
							}
							case 187:
							{
								field_idx = 0;
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								std::string s0 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s0.c_str(), s0.length());
								auto Sku = safe_parse<uint16_t>(parser, L"Sku");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "Sku", sizeof("Sku"));
								std::string s1 = std::to_string(Sku);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s1.c_str(), s1.length());
								auto BclMajorVersion = safe_parse<uint16_t>(parser, L"BclMajorVersion");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "BclMajorVersion", sizeof("BclMajorVersion"));
								std::string s2 = std::to_string(BclMajorVersion);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s2.c_str(), s2.length());
								auto BclMinorVersion = safe_parse<uint16_t>(parser, L"BclMinorVersion");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "BclMinorVersion", sizeof("BclMinorVersion"));
								std::string s3 = std::to_string(BclMinorVersion);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s3.c_str(), s3.length());
								auto BclBuildNumber = safe_parse<uint16_t>(parser, L"BclBuildNumber");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "BclBuildNumber", sizeof("BclBuildNumber"));
								std::string s4 = std::to_string(BclBuildNumber);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s4.c_str(), s4.length());
								auto BclQfeNumber = safe_parse<uint16_t>(parser, L"BclQfeNumber");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "BclQfeNumber", sizeof("BclQfeNumber"));
								std::string s5 = std::to_string(BclQfeNumber);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s5.c_str(), s5.length());
								auto VMMajorVersion = safe_parse<uint16_t>(parser, L"VMMajorVersion");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "VMMajorVersion", sizeof("VMMajorVersion"));
								std::string s6 = std::to_string(VMMajorVersion);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s6.c_str(), s6.length());
								auto VMMinorVersion = safe_parse<uint16_t>(parser, L"VMMinorVersion");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "VMMinorVersion", sizeof("VMMinorVersion"));
								std::string s7 = std::to_string(VMMinorVersion);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s7.c_str(), s7.length());
								auto VMBuildNumber = safe_parse<uint16_t>(parser, L"VMBuildNumber");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "VMBuildNumber", sizeof("VMBuildNumber"));
								std::string s8 = std::to_string(VMBuildNumber);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s8.c_str(), s8.length());
								auto VMQfeNumber = safe_parse<uint16_t>(parser, L"VMQfeNumber");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "VMQfeNumber", sizeof("VMQfeNumber"));
								std::string s9 = std::to_string(VMQfeNumber);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s9.c_str(), s9.length());
								auto StartupFlags = safe_parse<uint32_t>(parser, L"StartupFlags");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "StartupFlags", sizeof("StartupFlags"));
								std::string s10 = std::to_string(StartupFlags);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s10.c_str(), s10.length());
								auto StartupMode = safe_parse<uint8_t>(parser, L"StartupMode");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "StartupMode", sizeof("StartupMode"));
								std::string s11 = std::to_string(StartupMode);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s11.c_str(), s11.length());
								auto CommandLine = EDR::Util::wchar_to_char(safe_parse<std::wstring>(parser, L"CommandLine").c_str() );
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "CommandLine", sizeof("CommandLine"));
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, CommandLine.c_str(), CommandLine.length());
								auto RuntimeDllPath = EDR::Util::wchar_to_char(safe_parse<std::wstring>(parser, L"RuntimeDllPath").c_str() );
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "RuntimeDllPath", sizeof("RuntimeDllPath"));
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, RuntimeDllPath.c_str(), RuntimeDllPath.length());
								ELS.field.FieldCount = field_idx;
								break;
							}
							case 190:
							{
								auto MethodID = safe_parse<uint64_t>(parser, L"MethodID");
								auto ReJITID = safe_parse<uint64_t>(parser, L"ReJITID");
								auto MethodExtent = safe_parse<uint8_t>(parser, L"MethodExtent");
								auto CountOfMapEntries = safe_parse<uint16_t>(parser, L"CountOfMapEntries");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS.field.FieldCount = 5;
								std::string s0 = std::to_string(MethodID);
								std::string s1 = std::to_string(ReJITID);
								std::string s2 = std::to_string(MethodExtent);
								std::string s3 = std::to_string(CountOfMapEntries);
								std::string s4 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "MethodID", sizeof("MethodID"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "ReJITID", sizeof("ReJITID"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS.field.Fields[2].FieldName, "MethodExtent", sizeof("MethodExtent"));
								RtlCopyMemory(ELS.field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS.field.Fields[3].FieldName, "CountOfMapEntries", sizeof("CountOfMapEntries"));
								RtlCopyMemory(ELS.field.Fields[3].FieldValue, s3.c_str(), s3.length());
								RtlCopyMemory(ELS.field.Fields[4].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[4].FieldValue, s4.c_str(), s4.length());
								break;
							}
							case 200:
							{
								auto BytesAllocated = safe_parse<uint64_t>(parser, L"BytesAllocated");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS.field.FieldCount = 2;
								std::string s0 = std::to_string(BytesAllocated);
								std::string s1 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "BytesAllocated", sizeof("BytesAllocated"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								break;
							}
							case 201:
							{
								auto BytesFreed = safe_parse<uint64_t>(parser, L"BytesFreed");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS.field.FieldCount = 2;
								std::string s0 = std::to_string(BytesFreed);
								std::string s1 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "BytesFreed", sizeof("BytesFreed"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								break;
							}
							case 202:
							{
								auto HeapNum = safe_parse<uint32_t>(parser, L"HeapNum");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								auto Type = safe_parse<uint32_t>(parser, L"Type");
								auto Bytes = safe_parse<uint64_t>(parser, L"Bytes");
								ELS.field.FieldCount = 4;
								std::string s0 = std::to_string(HeapNum);
								std::string s1 = std::to_string(ClrInstanceID);
								std::string s2 = std::to_string(Type);
								std::string s3 = std::to_string(Bytes);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "HeapNum", sizeof("HeapNum"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS.field.Fields[2].FieldName, "Type", sizeof("Type"));
								RtlCopyMemory(ELS.field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS.field.Fields[3].FieldName, "Bytes", sizeof("Bytes"));
								RtlCopyMemory(ELS.field.Fields[3].FieldValue, s3.c_str(), s3.length());
								break;
							}
							case 203:
							{
								auto Heap = safe_parse<uint32_t>(parser, L"Heap");
								auto JoinTime = safe_parse<uint32_t>(parser, L"JoinTime");
								auto JoinType = safe_parse<uint32_t>(parser, L"JoinType");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								auto JoinID = safe_parse<uint32_t>(parser, L"JoinID");
								ELS.field.FieldCount = 5;
								std::string s0 = std::to_string(Heap);
								std::string s1 = std::to_string(JoinTime);
								std::string s2 = std::to_string(JoinType);
								std::string s3 = std::to_string(ClrInstanceID);
								std::string s4 = std::to_string(JoinID);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "Heap", sizeof("Heap"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "JoinTime", sizeof("JoinTime"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS.field.Fields[2].FieldName, "JoinType", sizeof("JoinType"));
								RtlCopyMemory(ELS.field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS.field.Fields[3].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[3].FieldValue, s3.c_str(), s3.length());
								RtlCopyMemory(ELS.field.Fields[4].FieldName, "JoinID", sizeof("JoinID"));
								RtlCopyMemory(ELS.field.Fields[4].FieldValue, s4.c_str(), s4.length());
								break;
							}
							case 204:
							{
								field_idx = 0;
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								std::string s0 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s0.c_str(), s0.length());
								auto FreeListAllocated = safe_parse<uint64_t>(parser, L"FreeListAllocated");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "FreeListAllocated", sizeof("FreeListAllocated"));
								std::string s1 = std::to_string(FreeListAllocated);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s1.c_str(), s1.length());
								auto FreeListRejected = safe_parse<uint64_t>(parser, L"FreeListRejected");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "FreeListRejected", sizeof("FreeListRejected"));
								std::string s2 = std::to_string(FreeListRejected);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s2.c_str(), s2.length());
								auto EndOfSegAllocated = safe_parse<uint64_t>(parser, L"EndOfSegAllocated");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "EndOfSegAllocated", sizeof("EndOfSegAllocated"));
								std::string s3 = std::to_string(EndOfSegAllocated);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s3.c_str(), s3.length());
								auto CondemnedAllocated = safe_parse<uint64_t>(parser, L"CondemnedAllocated");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "CondemnedAllocated", sizeof("CondemnedAllocated"));
								std::string s4 = std::to_string(CondemnedAllocated);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s4.c_str(), s4.length());
								auto PinnedAllocated = safe_parse<uint64_t>(parser, L"PinnedAllocated");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "PinnedAllocated", sizeof("PinnedAllocated"));
								std::string s5 = std::to_string(PinnedAllocated);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s5.c_str(), s5.length());
								auto PinnedAllocatedAdvance = safe_parse<uint64_t>(parser, L"PinnedAllocatedAdvance");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "PinnedAllocatedAdvance", sizeof("PinnedAllocatedAdvance"));
								std::string s6 = std::to_string(PinnedAllocatedAdvance);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s6.c_str(), s6.length());
								auto RunningFreeListEfficiency = safe_parse<uint32_t>(parser, L"RunningFreeListEfficiency");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "RunningFreeListEfficiency", sizeof("RunningFreeListEfficiency"));
								std::string s7 = std::to_string(RunningFreeListEfficiency);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s7.c_str(), s7.length());
								auto CondemnReasons0 = safe_parse<uint32_t>(parser, L"CondemnReasons0");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "CondemnReasons0", sizeof("CondemnReasons0"));
								std::string s8 = std::to_string(CondemnReasons0);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s8.c_str(), s8.length());
								auto CondemnReasons1 = safe_parse<uint32_t>(parser, L"CondemnReasons1");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "CondemnReasons1", sizeof("CondemnReasons1"));
								std::string s9 = std::to_string(CondemnReasons1);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s9.c_str(), s9.length());
								auto CompactMechanisms = safe_parse<uint32_t>(parser, L"CompactMechanisms");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "CompactMechanisms", sizeof("CompactMechanisms"));
								std::string s10 = std::to_string(CompactMechanisms);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s10.c_str(), s10.length());
								auto ExpandMechanisms = safe_parse<uint32_t>(parser, L"ExpandMechanisms");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ExpandMechanisms", sizeof("ExpandMechanisms"));
								std::string s11 = std::to_string(ExpandMechanisms);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s11.c_str(), s11.length());
								auto HeapIndex = safe_parse<uint32_t>(parser, L"HeapIndex");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "HeapIndex", sizeof("HeapIndex"));
								std::string s12 = std::to_string(HeapIndex);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s12.c_str(), s12.length());
								auto ExtraGen0Commit = safe_parse<uint64_t>(parser, L"ExtraGen0Commit");
								RtlCopyMemory(ELS.field.Fields[field_idx].FieldName, "ExtraGen0Commit", sizeof("ExtraGen0Commit"));
								std::string s13 = std::to_string(ExtraGen0Commit);
								RtlCopyMemory(ELS.field.Fields[field_idx++].FieldValue, s13.c_str(), s13.length());
								ELS.field.FieldCount = field_idx;
								break;
							}
							case 205:
							{
								auto FinalYoungestDesired = safe_parse<uint64_t>(parser, L"FinalYoungestDesired");
								auto NumHeaps = safe_parse<int32_t>(parser, L"NumHeaps");
								auto CondemnedGeneration = safe_parse<uint32_t>(parser, L"CondemnedGeneration");
								auto Gen0ReductionCount = safe_parse<uint32_t>(parser, L"Gen0ReductionCount");
								auto Reason = safe_parse<uint32_t>(parser, L"Reason");
								auto GlobalMechanisms = safe_parse<uint32_t>(parser, L"GlobalMechanisms");
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								auto PauseMode = safe_parse<uint32_t>(parser, L"PauseMode");
								auto MemoryPressure = safe_parse<uint32_t>(parser, L"MemoryPressure");
								ELS.field.FieldCount = 9;
								std::string s0 = std::to_string(FinalYoungestDesired);
								std::string s1 = std::to_string(NumHeaps);
								std::string s2 = std::to_string(CondemnedGeneration);
								std::string s3 = std::to_string(Gen0ReductionCount);
								std::string s4 = std::to_string(Reason);
								std::string s5 = std::to_string(GlobalMechanisms);
								std::string s6 = std::to_string(ClrInstanceID);
								std::string s7 = std::to_string(PauseMode);
								std::string s8 = std::to_string(MemoryPressure);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "FinalYoungestDesired", sizeof("FinalYoungestDesired"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "NumHeaps", sizeof("NumHeaps"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS.field.Fields[2].FieldName, "CondemnedGeneration", sizeof("CondemnedGeneration"));
								RtlCopyMemory(ELS.field.Fields[2].FieldValue, s2.c_str(), s2.length());
								RtlCopyMemory(ELS.field.Fields[3].FieldName, "Gen0ReductionCount", sizeof("Gen0ReductionCount"));
								RtlCopyMemory(ELS.field.Fields[3].FieldValue, s3.c_str(), s3.length());
								RtlCopyMemory(ELS.field.Fields[4].FieldName, "Reason", sizeof("Reason"));
								RtlCopyMemory(ELS.field.Fields[4].FieldValue, s4.c_str(), s4.length());
								RtlCopyMemory(ELS.field.Fields[5].FieldName, "GlobalMechanisms", sizeof("GlobalMechanisms"));
								RtlCopyMemory(ELS.field.Fields[5].FieldValue, s5.c_str(), s5.length());
								RtlCopyMemory(ELS.field.Fields[6].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[6].FieldValue, s6.c_str(), s6.length());
								RtlCopyMemory(ELS.field.Fields[7].FieldName, "PauseMode", sizeof("PauseMode"));
								RtlCopyMemory(ELS.field.Fields[7].FieldValue, s7.c_str(), s7.length());
								RtlCopyMemory(ELS.field.Fields[8].FieldName, "MemoryPressure", sizeof("MemoryPressure"));
								RtlCopyMemory(ELS.field.Fields[8].FieldValue, s8.c_str(), s8.length());
								break;
							}
							case 206:
							{
								auto GCName = EDR::Util::wchar_to_char(safe_parse<std::wstring>(parser, L"GCName").c_str() );
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS.field.FieldCount = 2;
								std::string s1 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "GCName", sizeof("GCName"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, GCName.c_str(), GCName.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								break;
							}
							case 250:
							case 252:
							case 254:
							{
								auto EntryEIP = safe_parse<uint64_t>(parser, L"EntryEIP");
								auto MethodID = safe_parse<uint64_t>(parser, L"MethodID");
								auto MethodName = EDR::Util::wchar_to_char(safe_parse<std::wstring>(parser, L"MethodName").c_str() );
								auto ClrInstanceID = safe_parse<uint16_t>(parser, L"ClrInstanceID");
								ELS.field.FieldCount = 4;
								std::string s0 = std::to_string(EntryEIP);
								std::string s1 = std::to_string(MethodID);
								std::string s3 = std::to_string(ClrInstanceID);
								RtlCopyMemory(ELS.field.Fields[0].FieldName, "EntryEIP", sizeof("EntryEIP"));
								RtlCopyMemory(ELS.field.Fields[0].FieldValue, s0.c_str(), s0.length());
								RtlCopyMemory(ELS.field.Fields[1].FieldName, "MethodID", sizeof("MethodID"));
								RtlCopyMemory(ELS.field.Fields[1].FieldValue, s1.c_str(), s1.length());
								RtlCopyMemory(ELS.field.Fields[2].FieldName, "MethodName", sizeof("MethodName"));
								RtlCopyMemory(ELS.field.Fields[2].FieldValue, MethodName.c_str(), MethodName.length());
								RtlCopyMemory(ELS.field.Fields[3].FieldName, "ClrInstanceID", sizeof("ClrInstanceID"));
								RtlCopyMemory(ELS.field.Fields[3].FieldValue, s3.c_str(), s3.length());
								break;
							}
							}
						}

                    
                };
            }
        }
    }
}


#endif