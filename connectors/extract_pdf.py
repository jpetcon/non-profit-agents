"""Short-lived document worker. Receives no application credentials or config."""
import io
import sys


def main():
    # Enforce CPU independently of the gateway event loop and its deadline.
    if sys.platform == 'win32':
        import ctypes
        from ctypes import wintypes
        class Basic(ctypes.Structure):
            _fields_ = [('process_time', ctypes.c_longlong), ('job_time', ctypes.c_longlong), ('flags', wintypes.DWORD), ('minimum', ctypes.c_size_t), ('maximum', ctypes.c_size_t), ('processes', wintypes.DWORD), ('affinity', ctypes.c_size_t), ('priority', wintypes.DWORD), ('scheduling', wintypes.DWORD)]
        class Counters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in ['read_ops', 'write_ops', 'other_ops', 'read_bytes', 'write_bytes', 'other_bytes']]
        class Limits(ctypes.Structure):
            _fields_ = [('basic', Basic), ('io', Counters), ('process_memory', ctypes.c_size_t), ('job_memory', ctypes.c_size_t), ('peak_process', ctypes.c_size_t), ('peak_job', ctypes.c_size_t)]
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.CreateJobObjectW.restype = wintypes.HANDLE
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        limits = Limits()
        limits.basic.process_time = 4 * 10000000
        limits.basic.flags = 0x2 | 0x100  # per-process CPU time and committed memory
        limits.process_memory = 256 * 1024 * 1024
        job = kernel.CreateJobObjectW(None, None)
        if not job or not kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)) or not kernel.AssignProcessToJobObject(job, kernel.GetCurrentProcess()):
            raise OSError('Worker resource limits unavailable')
        # Keep the handle alive until this short-lived worker exits.
    else:
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (4, 4))
        if sys.platform.startswith('linux'):
            resource.setrlimit(resource.RLIMIT_AS, (256*1024*1024, 256*1024*1024))
    from pypdf import PdfReader, apply_configuration
    maximum = 1024*1024
    data = sys.stdin.buffer.read(maximum+1)
    if len(data)>maximum:raise ValueError('Document too large')
    with apply_configuration(maximum_declared_stream_length=4*maximum, zlib_maximum_output_length=4*maximum, lzw_maximum_output_length=4*maximum, run_length_maximum_output_length=4*maximum, stream_decoding_work_maximum_length=8*maximum, stream_parsing_work_maximum_count=100000, xform_maximum_invocations_per_extraction=100):
        reader=PdfReader(io.BytesIO(data), strict=True, xref_stream_maximum_entries=100000)
        if reader.is_encrypted or len(reader.pages)>100:raise ValueError('Unsupported document')
        parts=[];size=0
        for page in reader.pages:
            text=page.extract_text() or ''
            size+=len(text.encode())
            if size>maximum:raise ValueError('Extracted document too large')
            parts.append(text)
        sys.stdout.write('\n'.join(parts))


if __name__=='__main__':
    try:main()
    except Exception:sys.exit(1)
