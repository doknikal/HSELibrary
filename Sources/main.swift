// HSE Library — native menubar proxy client (no scripts).
// Swift + Network.framework; credentials live in Keychain only.
import Cocoa
import Network
import Security

// MARK: - Constants

enum Cfg {
    static let upstreamHost = "libtest.hse.ru"
    static let upstreamPort: UInt16 = 3128
    static let listenPort: UInt16 = 18080
    static let keychainService = "libtest.hse.ru"
    static let keychainLabel = "HSE Library Proxy"
    static let listURL = URL(string: "https://libtest.hse.ru/www.txt")!
    static let testURL = URL(string: "https://www.jstor.org/")!
    static let newsURL = URL(string: "https://eivis.ru/browse/publication/41506/udb/1")!
}

// MARK: - Domain list

struct DomainList {
    var exact = Set<String>()
    var suffix = Set<String>()

    var count: Int { exact.count + suffix.count }

    mutating func parse(_ text: String) {
        exact.removeAll(keepingCapacity: true)
        suffix.removeAll(keepingCapacity: true)
        for rawLine in text.split(separator: "\n") {
            let line = rawLine.trimmingCharacters(in: .whitespaces).lowercased()
                .trimmingCharacters(in: CharacterSet(charactersIn: "\r"))
            guard !line.isEmpty, !line.hasPrefix("#") else { continue }
            if line.hasPrefix(".") {
                let s = String(line.dropFirst())
                if !s.isEmpty { suffix.insert(s) }
            } else {
                exact.insert(line)
            }
        }
    }

    func contains(_ host: String) -> Bool {
        let h = host.lowercased()
        if exact.contains(h) { return true }
        for s in suffix where h == s || h.hasSuffix("." + s) { return true }
        return false
    }
}

// MARK: - Keychain (Security framework, in-process; no CLI, no plaintext files)

enum Keychain {
    private static var query: [String: Any] {
        [kSecClass as String: kSecClassInternetPassword,
         kSecAttrServer as String: Cfg.keychainService,
         kSecAttrLabel as String: Cfg.keychainLabel]
    }

    static func read() -> (account: String, password: String)? {
        var q = query
        q[kSecReturnAttributes as String] = true
        q[kSecReturnData as String] = true
        var item: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess,
              let dict = item as? [String: Any],
              let account = dict[kSecAttrAccount as String] as? String,
              let data = dict[kSecValueData as String] as? Data,
              let password = String(data: data, encoding: .utf8),
              !account.isEmpty, !password.isEmpty else { return nil }
        return (account, password)
    }

    static func save(account: String, password: String) -> Bool {
        SecItemDelete(query as CFDictionary)
        var add = query
        add[kSecAttrAccount as String] = account
        add[kSecValueData as String] = Data(password.utf8)
        return SecItemAdd(add as CFDictionary, nil) == errSecSuccess
    }

    static func delete() {
        SecItemDelete(query as CFDictionary)
    }
}

// MARK: - networksetup (fixed argv, no shell)

enum NetSetup {
    static func run(_ arguments: [String]) -> String? {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
        p.arguments = arguments
        let out = Pipe()
        p.standardOutput = out
        p.standardError = Pipe()
        do { try p.run(); p.waitUntilExit() } catch { return nil }
        guard p.terminationStatus == 0 else { return nil }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8)
    }

    static func services() -> [String] {
        guard let text = run(["-listallnetworkservices"]), !text.isEmpty else { return [] }
        return text.split(separator: "\n").dropFirst()
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("*") }
    }

    static func setManualProxy(on: Bool) {
        for svc in services() {
            if on {
                _ = run(["-setwebproxy", svc, "127.0.0.1", String(Cfg.listenPort)])
                _ = run(["-setsecurewebproxy", svc, "127.0.0.1", String(Cfg.listenPort)])
                _ = run(["-setautoproxystate", svc, "off"])
            } else {
                _ = run(["-setwebproxystate", svc, "off"])
                _ = run(["-setsecurewebproxystate", svc, "off"])
            }
        }
    }
}


// MARK: - POSIX connection (Network.framework outbound is broken on this system)

final class PosixConn {
    var onReady: (() -> Void)?
    var onData: ((Data) -> Void)?
    var onClosed: (() -> Void)?
    private var fd: Int32 = -1
    private var wbuf = Data()
    private var readSource: DispatchSourceRead?
    private var writeSource: DispatchSourceWrite?
    private var timer: DispatchSourceTimer?
    private var connectTimer: DispatchSourceTimer?
    private let queue: DispatchQueue
    private let squeue = DispatchQueue(label: "ru.hse.library.posix")
    private var ready = false
    private var closed = false

    init(host: String, port: UInt16, queue: DispatchQueue, timeout: Double = 12,
         completion: @escaping (Bool) -> Void) {
        self.queue = queue
        DispatchQueue.global().async { [weak self] in
            var hints = addrinfo()
            hints.ai_socktype = SOCK_STREAM
            var res: UnsafeMutablePointer<addrinfo>?
            var saCopy: Data?
            if getaddrinfo(host, String(port), &hints, &res) == 0, let rp = res, rp.pointee.ai_addrlen > 0, let addr = rp.pointee.ai_addr {
                let n = Int(rp.pointee.ai_addrlen)
                saCopy = Data(bytes: UnsafeRawPointer(addr), count: n)
            }
            if res != nil { freeaddrinfo(res) }
            guard let sa = saCopy else {
                queue.async { completion(false) }
                return
            }
            self?.squeue.async { self?.connect(sa: sa, completion: completion) }
            _ = timeout
        }
    }

    private func connect(sa: Data, completion: @escaping (Bool) -> Void) {
        let s = sa.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) -> Int32 in
            let family = ptr.load(as: sockaddr_in.self).sin_family
            return Darwin.socket(Int32(family), SOCK_STREAM, 0)
        }
        fd = s
        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
        let rc = sa.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) -> Int32 in
            let sp = ptr.baseAddress!.assumingMemoryBound(to: sockaddr.self)
            return Darwin.connect(fd, sp, socklen_t(ptr.count))
        }
        let timer = DispatchSource.makeTimerSource(queue: squeue)
        timer.schedule(deadline: .now() + 12)
        timer.setEventHandler { [weak self] in self?.die() }
        timer.resume()
        self.timer = timer
        if rc == 0 {
            connected(completion)
        } else if errno == EINPROGRESS {
            let myFD = fd
            let thread = Thread {
                let start = Date()
                var linked = false
                while Date().timeIntervalSince(start) < 12 {
                    var err: Int32 = 0
                    var len = socklen_t(MemoryLayout<Int32>.size)
                    getsockopt(myFD, SOL_SOCKET, SO_ERROR, &err, &len)
                    var peer = sockaddr()
                    var plen = socklen_t(MemoryLayout<sockaddr>.size)
                    let pn = getpeername(myFD, &peer, &plen)
                    if err == 0 && pn == 0 { linked = true; break }
                    if err != 0 && err != EINPROGRESS { break }
                    usleep(100_000)
                }
                self.squeue.async {
                    guard !self.closed, !self.ready, self.fd == myFD else { return }
                    if linked { self.connected(completion) } else { self.die() }
                }
            }
            thread.start()
        } else {
            die()
        }
    }

    private func connected(_ completion: (Bool) -> Void) {
        timer?.cancel(); timer = nil
        ready = true
        let r = DispatchSource.makeReadSource(fileDescriptor: fd, queue: squeue)
        r.setEventHandler { [weak self] in self?.drain() }
        r.resume()
        readSource = r
        completion(true)
        onReady?()
    }

    private func drain() {
        var buf = [UInt8](repeating: 0, count: 1 << 16)
        let n = buf.withUnsafeMutableBufferPointer { m -> Int in
            Darwin.read(fd, m.baseAddress, m.count)
        }
        if n > 0 {
            onData?(Data(buf[0..<n]))
        } else if n == 0 {
            die()
        } else if errno != EAGAIN {
            die()
        }
    }

    func write(_ data: Data) {
        guard !closed, ready else { NSLog("HSE: write blocked closed=%d ready=%d", closed ? 1 : 0, ready ? 1 : 0); if !closed { die() }; return }
        wbuf.append(data)
        flush()
        if !wbuf.isEmpty, writeSource == nil {
            let w = DispatchSource.makeWriteSource(fileDescriptor: fd, queue: squeue)
            w.setEventHandler { [weak self] in self?.flush(); if let self, self.wbuf.isEmpty { self.writeSource?.cancel(); self.writeSource = nil } }
            w.resume()
            writeSource = w
        }
    }

    private func flush() {
        while !wbuf.isEmpty {
            let n = wbuf.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) -> Int in
                Darwin.write(fd, ptr.baseAddress, ptr.count)
            }
            if n > 0 { wbuf.removeFirst(n) }
            else if n < 0 && errno == EAGAIN { break }
            else if n <= 0 { NSLog("HSE: posix flush fail n=%d errno=%d", n, errno); die(); return }
        }
    }

    private func die() {
        closed = true
        readSource?.cancel(); writeSource?.cancel(); timer?.cancel()
        connectTimer?.cancel()
        if fd >= 0 { Darwin.close(fd); fd = -1 }
        onClosed?()
    }

    func close() { die() }
}

// MARK: - Relay (native CONNECT proxy with HSE whitelist)

final class Relay {
    static let shared = Relay()
    private let queue = DispatchQueue(label: "ru.hse.library.relay")
    private var listener: NWListener?
    private var clients: [ClientConn] = []
    private let lockQueue = DispatchQueue(label: "ru.hse.library.lock")
    var domains = DomainList()
    private(set) var authHeader = ""

    var queueForClients: DispatchQueue { queue }
    var isRunning: Bool { listener != nil }

    func updateAuth() {
        if let cred = Keychain.read() {
            authHeader = "Basic " + Data("\(cred.account):\(cred.password)".utf8).base64EncodedString()
        } else { authHeader = "" }
    }

    func updateDomains(_ list: DomainList) { queue.async { self.domains = list } }

    func start() {
        queue.async {
            guard self.listener == nil else { return }
            do {
                let params = NWParameters.tcp
                params.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: Cfg.listenPort)!)
                let l = try NWListener(using: params)
                l.newConnectionHandler = { [weak self] c in self?.queue.async { self?.accept(c) } }
                l.stateUpdateHandler = { [weak self] state in
                    if case .failed = state { self?.queue.async { self?.stopInternal() } }
                }
                l.start(queue: self.queue)
                self.listener = l
                NSLog("HSE: relay started")
            } catch {
                NSLog("relay listen error: %@", error.localizedDescription)
            }
        }
    }

    func stop() { queue.async { self.stopInternal() } }

    private func stopInternal() {
        listener?.cancel()
        listener = nil
        lockQueue.async {
            self.clients.forEach { $0.finish() }
            self.clients.removeAll()
        }
    }

    private func accept(_ conn: NWConnection) {
        let c = ClientConn(conn: conn, relay: self)
        lockQueue.async { self.clients.append(c) }
        c.start()
    }

    fileprivate func remove(_ c: ClientConn) { lockQueue.async { self.clients.removeAll { $0 === c } } }

    fileprivate func whitelisted(_ host: String) -> Bool { domains.contains(host) }
    fileprivate func auth() -> String { authHeader }
}

final class ClientConn {
    private let relay: Relay
    let conn: NWConnection
    private var remote: PosixConn?
    private var buf = Data()
    private var extraUpstream = Data()
    private var kind = Kind.connect
    private enum Kind { case connect, absolute }
    private var phase = Phase.readingRequest
    private var done = false

    enum Phase { case readingRequest, awaitingUpstream, tunnel }

    let cqueue: DispatchQueue
    init(conn: NWConnection, relay: Relay) {
        self.conn = conn
        self.relay = relay
        self.cqueue = DispatchQueue(label: "ru.hse.library.client", attributes: .concurrent)
    }

    func start() {
        conn.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                guard self.isLoopback() else { self.finish(); return }
                if self.phase == .readingRequest { self.recv() }
            case .failed, .cancelled:
                self.finish()
            default: break
            }
        }
        conn.start(queue: cqueue)
        cqueue.async { [weak self] in
            if let self, self.conn.state == .ready, self.phase == .readingRequest {
                self.recv()
            }
        }
    }

    private func isLoopback() -> Bool {
        guard let ep = conn.currentPath?.remoteEndpoint else { return true }
        return ep.debugDescription.contains("127.0.0.1")
    }

    private func recv() {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 1 << 16) { [weak self] data, _, complete, error in
            guard let self else { return }
            if let d = data, !d.isEmpty { self.buf.append(d) }
            if error != nil { self.finish(); return }
            self.onBytes()
            if complete && self.phase != .tunnel { self.finish() }
        }
    }

    private func onBytes() {
        switch phase {
        case .readingRequest:
            guard let range = buf.range(of: Data("\r\n\r\n".utf8)) else {
                if buf.count > 32 * 1024 { finish() } else { recv() }
                return
            }
            let head = buf.subdata(in: buf.startIndex..<range.lowerBound)
            let leftover = buf.subdata(in: range.upperBound..<buf.endIndex)
            buf = leftover
            handleRequest(headText: String(data: head, encoding: .utf8) ?? "", leftover: leftover)
        case .awaitingUpstream:
            guard let range = buf.range(of: Data("\r\n\r\n".utf8)) else { return }
            let head = buf.subdata(in: buf.startIndex..<range.lowerBound)
            let extra = buf.subdata(in: range.upperBound..<buf.endIndex)
            buf = Data()
            let statusLine = String(data: head, encoding: .utf8) ?? ""
            if statusLine.contains(" 200 ") {
                remote?.onData = { [weak self] d in self?.clientSend(d) }
                conn.send(content: Data("HTTP/1.1 200 Connection established\r\n\r\n".utf8),
                          completion: .contentProcessed { [weak self] _ in
                    guard let self, let remote = self.remote else { return }
                    if !extra.isEmpty { self.clientSend(extra) }
                    self.enterTunnel()
                })
            } else {
                conn.send(content: Data("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n".utf8),
                          completion: .contentProcessed { [weak self] _ in self?.finish() })
            }
        case .tunnel:
            break
        }
    }

    private func handleRequest(headText: String, leftover: Data) {
        let lines = headText.components(separatedBy: "\r\n")
        let parts = (lines.first ?? "").split(separator: " ")
        guard parts.count >= 2 else { finish(); return }
        let method = String(parts[0]).uppercased()
        let target = String(parts[1])

        if method == "CONNECT" {
            let hp = target.split(separator: ":", maxSplits: 1)
            let host = hp.first.map(String.init) ?? target
            let port = UInt16(hp.count > 1 ? String(hp[1]) : "443") ?? 443
            if relay.whitelisted(host) && !relay.auth().isEmpty {
                connectRemote(host: Cfg.upstreamHost, port: Cfg.upstreamPort, kind: .connect) { [weak self] ok in
                    guard let self, ok, let remote = self.remote else { self?.fail502(); return }
                    let auth = self.relay.auth()
                    let preface = "CONNECT \(host):\(port) HTTP/1.1\r\nHost: \(host):\(port)\r\nProxy-Authorization: \(auth)\r\n\r\n"
                    self.buf = leftover
                    self.phase = .awaitingUpstream
                    remote.onData = { [weak self] d in
                        guard let self, self.phase == .awaitingUpstream else {
                            self?.remoteWrite(d); return
                        }
                        self.buf.append(d)
                        if self.buf.range(of: Data("\r\n\r\n".utf8)) != nil { self.onBytes() }
                    }
                    remote.onClosed = { [weak self] in self?.finish() }
                    remote.write(Data(preface.utf8))
                }
            } else {
                connectRemote(host: host, port: port, kind: .connect) { [weak self] ok in
                    guard let self, ok, let remote = self.remote else { self?.fail502(); return }
                    remote.onData = { [weak self] d in self?.clientSend(d) }
                    remote.onClosed = { [weak self] in self?.finish() }
                    self.clientSend(Data("HTTP/1.1 200 Connection established\r\n\r\n".utf8))
                    if !leftover.isEmpty { remote.write(leftover) }
                    self.enterTunnel()
                }
            }
        } else if method == "GET" || method == "HEAD" || method == "POST" || method == "PUT" || method == "DELETE" {
            guard let m = try? NSRegularExpression(pattern: "^https?://([^/:]+)(:\\d+)?(/.*)$"),
                  let mm = m.firstMatch(in: target, range: NSRange(target.startIndex..., in: target)) else { finish(); return }
            let host = String(target[Range(mm.range(at: 1), in: target)!])
            let portStr = mm.range(at: 2).location != NSNotFound ? String(target[Range(mm.range(at: 2), in: target)!]).dropFirst() : "80"
            let rest = String(target[Range(mm.range(at: 3), in: target)!])
            if relay.whitelisted(host) {
                conn.send(content: Data("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".utf8),
                          completion: .contentProcessed { [weak self] _ in self?.finish() })
                return
            }
            connectRemote(host: host, port: UInt16(portStr) ?? 80, kind: .absolute) { [weak self] ok in
                guard let self, ok, let remote = self.remote else { self?.fail502(); return }
                let req = "\(method) \(rest.isEmpty ? "/" : rest) HTTP/1.1\r\nHost: \(host)\r\nConnection: close\r\n\r\n"
                var out = Data(req.utf8)
                out.append(leftover)
                remote.onData = { [weak self] d in self?.clientSend(d) }
                remote.onClosed = { [weak self] in self?.finish() }
                remote.write(out)
                self.phase = .tunnel
                self.recvFromClientIntoRemote()
            }
        } else {
            fail502()
        }
    }

    private func connectRemote(host: String, port: UInt16, kind: Kind, completion: @escaping (Bool) -> Void) {
        self.kind = kind
        let r = PosixConn(host: host, port: port, queue: cqueue) { [weak self] ok in
            completion(ok)
        }
        remote = r
        r.onClosed = { [weak self] in self?.finish() }
    }

    private func enterTunnel() {
        phase = .tunnel
        recvFromClientIntoRemote()
    }

    private func recvFromClientIntoRemote() {
        guard !done, let remote else { return }
        conn.receive(minimumIncompleteLength: 1, maximumLength: 1 << 16) { [weak self] d, _, complete, error in
            guard let self else { return }
            if let d = d, !d.isEmpty, !self.done { self.remote?.write(d) }
            if complete || error != nil { self.finish() } else if !self.done { self.recvFromClientIntoRemote() }
        }
    }

    private func clientSend(_ data: Data) {
        guard !done else { return }
        conn.send(content: data, completion: .contentProcessed { [weak self] _ in })
    }

    private func remoteWrite(_ data: Data) {
        guard !done else { return }
        remote?.write(data)
    }

    private func fail502() {
        conn.send(content: Data("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n".utf8),
                  completion: .contentProcessed { [weak self] _ in self?.finish() })
    }

    func finish() {
        guard !done else { return }
        done = true
        conn.cancel()
        remote?.close()
        Relay.shared.remove(self)
    }
}

// MARK: - Domain list fetch

enum ListFetcher {
    static func fetch(completion: @escaping (DomainList?) -> Void) {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.connectionProxyDictionary = [:]   // list fetch must bypass our own relay
        let task = URLSession(configuration: cfg).dataTask(with: Cfg.listURL) { data, resp, _ in
            guard let data, let http = resp as? HTTPURLResponse, http.statusCode == 200,
                  let text = String(data: data, encoding: .utf8) else {
                completion(nil); return
            }
            var list = DomainList()
            list.parse(text)
            completion(list)
        }
        task.resume()
    }
}

// MARK: - Access test (through upstream proxy with Keychain credentials)

final class AccessTester: NSObject, URLSessionDataDelegate {
    var retained: AnyObject?
    func test(completion: @escaping (String) -> Void) {
        guard let cred = Keychain.read() else { completion("No saved login. Sign in from the menu first."); return }
        let config = URLSessionConfiguration.ephemeral
        config.connectionProxyDictionary = [
            "HTTPEnable": 1,
            "HTTPProxy": Cfg.upstreamHost,
            "HTTPPort": Int(Cfg.upstreamPort),
            "HTTPSEnable": 1,
            "HTTPSProxy": Cfg.upstreamHost,
            "HTTPSPort": Int(Cfg.upstreamPort),
        ]
        let session = URLSession(configuration: config, delegate: self, delegateQueue: nil)
        retained = session
        let task = session.dataTask(with: Cfg.testURL) { _, resp, error in
            if let error { completion("Server unreachable: \(error.localizedDescription)"); return }
            let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
            switch code {
            case 200...399: completion("Enjoy your HSE library access!")
            case 407: completion("Wrong login or password (407).")
            default: completion("Error: HTTP \(code)")
            }
        }
        task.resume()
    }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                   didReceive challenge: URLAuthenticationChallenge,
                   completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if challenge.protectionSpace.host == Cfg.upstreamHost,
           let cred = Keychain.read() {
            completionHandler(.useCredential,
                               URLCredential(user: cred.account, password: cred.password, persistence: .none))
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }
}

// MARK: - App delegate: menubar UI

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem!
    private let tester = AccessTester()
    private var enabled = UserDefaults.standard.object(forKey: "HSEProxyEnabled") as? Bool ?? false

    private var domains = DomainList()

    private var proxyMenuItem: NSMenuItem!
    private var infoMenuItem: NSMenuItem!
    private var loginMenuItem: NSMenuItem!

    var proxyOn: Bool {
        get { enabled }
        set {
            enabled = newValue
            UserDefaults.standard.set(newValue, forKey: "HSEProxyEnabled")
        }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let path = Bundle.main.path(forResource: "AppIcon", ofType: "icns"),
           let img = NSImage(contentsOfFile: path) {
            img.size = NSSize(width: 18, height: 18)
            statusItem.button?.image = img
        } else {
            statusItem.button?.title = "HSE"
        }
        let menu = NSMenu()
        menu.delegate = self
        // importance order: proxy toggle first, sign-in below
        proxyMenuItem = NSMenuItem(title: "Enable proxy", action: #selector(toggleProxy), keyEquivalent: "")
        proxyMenuItem.target = self
        menu.addItem(proxyMenuItem)
        menu.addItem(.separator())
        infoMenuItem = NSMenuItem(title: "…", action: nil, keyEquivalent: "")
        infoMenuItem.isEnabled = false
        menu.addItem(infoMenuItem)
        let testItem = NSMenuItem(title: "Test access", action: #selector(testAccess), keyEquivalent: "")
        testItem.target = self
        menu.addItem(testItem)
        loginMenuItem = NSMenuItem(title: "Sign in (HSE login)…", action: #selector(loginAction), keyEquivalent: "")
        loginMenuItem.target = self
        menu.addItem(loginMenuItem)
        let updateItem = NSMenuItem(title: "Refresh resource list", action: #selector(refreshList), keyEquivalent: "")
        updateItem.target = self
        menu.addItem(updateItem)
        menu.addItem(.separator())
        let openItem = NSMenuItem(title: "Vedomosti (IVIS archive)", action: #selector(openNews), keyEquivalent: "")
        openItem.target = self
        menu.addItem(openItem)
        menu.addItem(.separator())
        let quitItem = NSMenuItem(title: "Quit (disables proxy)", action: #selector(quitAction), keyEquivalent: "q")
        quitItem.target = self
        menu.addItem(quitItem)
        statusItem.menu = menu

        ListFetcher.fetch { [weak self] list in
            DispatchQueue.main.async {
                guard let self else { return }
                if let list { self.domains = list; Relay.shared.updateDomains(list) }
                self.updateMenuTitles()
                if self.proxyOn { self.enable() }
            }
        }
    }

    private func refreshDomains() {
        ListFetcher.fetch { [weak self] list in
            DispatchQueue.main.async {
                guard let self else { return }
                if let list { self.domains = list; Relay.shared.updateDomains(list) }
                self.updateMenuTitles()
            }
        }
    }

    private func updateMenuTitles() {
        let relayRunning = Relay.shared.isRunning
        proxyMenuItem.title = relayRunning ? "Disable proxy" : "Enable proxy"
        statusItem?.button?.alphaValue = relayRunning ? 1.0 : 0.35
        let login = Keychain.read()?.account
        let loginPart = login.map { "\($0)" } ?? "not signed in"
        infoMenuItem.title = "Proxy: \(relayRunning ? "on" : "off") · Resources: \(domains.count) · Login: \(loginPart)"
        loginMenuItem.title = (Keychain.read() == nil) ? "Sign in (HSE login)…" : "Change HSE login…"
    }

    private func enable() {
        guard Keychain.read() != nil else {
            proxyOn = false
            DispatchQueue.main.async { self.updateMenuTitles() }
            return
        }
        Relay.shared.updateAuth()
        if domains.count == 0 {
            // try to keep whatever is cached; fetch below will refresh
        }
        Relay.shared.updateDomains(domains)
        Relay.shared.start()
        NetSetup.setManualProxy(on: true)
        proxyOn = true
        DispatchQueue.main.async { self.updateMenuTitles() }
    }

    private func disable() {
        NetSetup.setManualProxy(on: false)
        Relay.shared.stop()
        proxyOn = false
        DispatchQueue.main.async { self.updateMenuTitles() }
    }

    @objc private func toggleProxy() {
        if Relay.shared.isRunning { disable() } else { enable() }
    }

    @objc private func loginAction() {
        let alert = NSAlert()
        alert.messageText = "HSE Library sign-in"
        alert.informativeText = "Your login and password are stored only in the macOS Keychain."
        alert.addButton(withTitle: "Save")
        alert.addButton(withTitle: "Cancel")
        let box = NSStackView()
        box.orientation = .vertical
        box.spacing = 8
        let loginField = NSTextField()
        loginField.placeholderString = "HSE login (e.g. ivanov@edu.hse.ru)"
        if let cur = Keychain.read() { loginField.stringValue = cur.account }
        let passField = NSSecureTextField()
        passField.placeholderString = "Password"
        box.addArrangedSubview(loginField)
        box.addArrangedSubview(passField)
        alert.accessoryView = box
        alert.window.initialFirstResponder = (Keychain.read() == nil) ? loginField : passField
        if alert.runModal() == .alertFirstButtonReturn {
            let account = loginField.stringValue.trimmingCharacters(in: .whitespaces)
            let password = passField.stringValue
            guard !account.isEmpty, !password.isEmpty else { return }
            if Keychain.save(account: account, password: password) {
                Relay.shared.updateAuth()
                updateMenuTitles()
            }
        }
    }

    @objc private func testAccess() {
        tester.test { [weak self] message in
            DispatchQueue.main.async {
                let alert = NSAlert()
                alert.messageText = message
                alert.runModal()
                self?.updateMenuTitles()
            }
        }
    }

    @objc private func refreshList() {
        refreshDomains()
    }

    @objc private func openNews() {
        NSWorkspace.shared.open(Cfg.newsURL)
    }

    @objc private func quitAction() {
        if Relay.shared.isRunning { disable() }
        NSApp.terminate(self)
    }
}

extension AppDelegate: NSMenuDelegate {
    func menuNeedsUpdate(_ menu: NSMenu) { updateMenuTitles() }
}

// MARK: - Bootstrap

private var retainedDelegate: AppDelegate!

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
retainedDelegate = AppDelegate()
app.delegate = retainedDelegate
app.run()
