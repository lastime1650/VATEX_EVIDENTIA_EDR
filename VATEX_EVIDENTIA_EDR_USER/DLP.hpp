#ifndef USER_DLP_HPP
#define USER_DLP_HPP

#include "Util.hpp"

#include "IOCTL.hpp"

#include <filesystem>

#include <map>
/*
	File Reference Number������� ���� �ĺ�
*/
namespace DLP
{


	namespace Policy
	{
		typedef struct DLP_Policy
		{
			BOOLEAN is_writable = TRUE;						//�бⰡ �����Ѱ�?
			BOOLEAN is_readable = TRUE;						// ���Ⱑ �����Ѱ�?

			BOOLEAN is_can_be_other_processaccess = TRUE;	// �ٸ� ���μ����� �ش� ���Ͽ� <��ȣ�ۿ�> �����Ѱ�?

		}DLP_Policy, *PDLP_Policy;
	}

#define FRN_ID_SIZE 16
	typedef CHAR FRN_ID;

	struct FRN_INFO
	{
		ULONG64 FRN = 0;	// 0~ 8
		ULONG64 Extend = 0; // 8~ 16

		// map Ű �񱳿�
		bool operator<(const FRN_INFO& other) const noexcept
		{
			if (FRN < other.FRN)
				return true;
			else if (FRN > other.FRN)
				return false;
			return Extend < other.Extend;
		}
	};

	struct FilePathStruct
	{
		std::string FullPath;
		std::string DirPath;
		std::string FileName;
	};

	struct DLPINFO
	{
		FilePathStruct Path;
		FRN_INFO File_Identifier = {0,0};
	};



	class DLP_USER_Manager
	{
	public:
		DLP_USER_Manager(std::string DLPFileFolder = "C:\\VATEX_DLP_FILE_FOLDER\\")
			: DLP_File_Folder(DLPFileFolder)
		{
			this->_CreateDirectories(DLPFileFolder); // ���� ���� ����


		}
		~DLP_USER_Manager() { ioctl.~IOCTL(); }

		BOOLEAN File_Load(const PCHAR FileFullPath)
		{
			if (!FileFullPath)
				return FALSE;

			std::string str_FileFullPath(FileFullPath);
			if (str_FileFullPath.empty())
				return FALSE;

			struct FilePathStruct ParsedFilePath;
			if (!_ParseFilePath(str_FileFullPath, ParsedFilePath))
				return FALSE;

			struct DLPINFO OutPut_INFO;
			if (!_Get_File_to_DLPINFO(ParsedFilePath, &OutPut_INFO))
				return FALSE;

			DLP_Map[OutPut_INFO.File_Identifier] = ParsedFilePath;

			return TRUE;
		}

	private:
		EDR::IOCTL::IOCTL ioctl;

		std::string DLP_File_Folder;
		std::map<struct FRN_INFO, struct FilePathStruct > DLP_Map;

		BOOLEAN _Get_File_to_DLPINFO(const struct FilePathStruct& Path, struct DLPINFO* OutPut_INFO)
		{
			if (!OutPut_INFO)
				return FALSE;

			HANDLE hFile = CreateFileA(
				Path.FullPath.c_str(),
				GENERIC_READ,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
				NULL,
				OPEN_EXISTING,
				FILE_FLAG_BACKUP_SEMANTICS,
				NULL
			);
			if (!hFile || hFile == INVALID_HANDLE_VALUE)
				return FALSE;

			FILE_ID_INFO info = { 0 };
			if (!GetFileInformationByHandleEx(
				hFile,
				FileIdInfo,
				&info,
				sizeof(info)
			))
			{
				CloseHandle(hFile);
				return FALSE;
			}

			// FRN
			RtlCopyMemory(
				(PUCHAR)(&OutPut_INFO->File_Identifier.FRN),
				(PUCHAR)(info.FileId.Identifier),
				8
			);

			// Extended FRN
			RtlCopyMemory(
				(PUCHAR)(&OutPut_INFO->File_Identifier.Extend),
				(PUCHAR)((PUCHAR)info.FileId.Identifier + 8),
				8
			);

			CloseHandle(hFile);
			return TRUE;
		}

		// �߰� ���� ���� (��� �ƴ�)
		/*
			< Example >
			-> "C:\A\B\C\target.exe
			�� ��,

			index0: C:\
			index1: C:\A\
			index2: C:\A\B\
			index3: C:\A\B\C\
			index4: C:\A\B\C\target.exe

			* �� ���� \�� �־ ���͸��� ���� �� ����.
		*/
		bool _CreateDirectories(const std::string& path)
		{
			ULONG64 index = 0;
			std::string tmp;
			for (size_t i = 0; i < path.size(); ++i)
			{
				tmp += path[i];

				// ���͸� ������ ������ �� �������� ���� ����
				if (path[i] == '\\' || path[i] == '/')
				{
					if (index == 0)
					{
						++index;
						continue;
					}

					std::cout << tmp << std::endl;

					CreateDirectoryA(
						tmp.c_str(),
						NULL
					);
				}
			}

			return true;
		}

		BOOLEAN _ParseFilePath(std::string fullpath, struct FilePathStruct& Path)
		{

			if (fullpath.empty()) return FALSE;

			Path.FullPath = fullpath;

			try {
				std::filesystem::path p(fullpath);
				Path.DirPath = p.parent_path().string();
				Path.FileName = p.filename().string();
			}
			catch (...) {
				// ���� �� FullPath�� ����
				Path.DirPath.clear();
				Path.FileName.clear();
				return FALSE;
			}

			return TRUE;
		}

	};



}

#endif