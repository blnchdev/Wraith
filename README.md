# Wraith

A handle hijacking implementation for a given process, using [Aether](https://github.com/blnchdev/Aether) as the dynamic direct syscall wrapper.  
There's no practical need to use direct syscalls in your own process for handle hijacking, but it's an interesting exercise nonetheless.  
This implementation uses std::optional because I think it's underappreciated!

## Notes
This is for educational purposes only. Handle hijacking is typically either blocked or detected by EDRs and kernel-mode anti-cheat solutions, so this technique has limited real-world applicability.

### Credits
[NtDoc](https://ntdoc.m417z.com/) for NtAPI Definitions
