import React, { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer,
  PieChart, Pie, Cell,
} from 'recharts';
import { Shield, Server, Cpu, Activity, Lock, AlertTriangle, Terminal, XOctagon, FileText, X } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import remarkMath from 'remark-math';
import rehypeKatex from 'rehype-katex';
import 'katex/dist/katex.min.css';
import originalPaper from '../../../docs/paper.md?raw';
import englishPaper from '../../../docs/paper_en.md?raw';

const Dashboard = () => {
  // --- States for Architecture Flow & Attack Simulator ---
  const [isSimulating, setIsSimulating] = useState(false);
  const [packetStage, setPacketStage] = useState(0); 
  const [currentScenario, setCurrentScenario] = useState<'normal' | 'hijack' | 'replay' | 'tamper' | null>(null);

  // --- States for Paper Modal ---
  const [isPaperOpen, setIsPaperOpen] = useState(false);
  const [paperLang, setPaperLang] = useState<'ko' | 'en'>('en');
  const paperContent = paperLang === 'ko' ? originalPaper : englishPaper;

  // --- States for Logs ---
  const [logs, setLogs] = useState<{id: number, time: string, type: 'success' | 'error' | 'info', message: string}[]>([]);
  const logsEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);
  
  const addLog = (type: 'success' | 'error' | 'info', message: string) => {
    const newLog = {
      id: Date.now() + Math.random(),
      time: new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit', fractionalSecondDigits: 2 }),
      type,
      message,
    };
    setLogs(prev => [...prev, newLog].slice(-20));
  };

  const runSimulation = (scenario: 'normal' | 'hijack' | 'replay' | 'tamper') => {
    if (isSimulating) return;
    setIsSimulating(true);
    setCurrentScenario(scenario);
    
    // Step 1: Client Node
    setPacketStage(1);
    addLog('info', `[Client] Initiating request for ${scenario.toUpperCase()} scenario...`);
    
    if (scenario === 'normal') {
      setTimeout(() => {
        addLog('info', '[TPM] Hardware signing complete. (ECDSA P-256)');
        setPacketStage(2); // Move to Gateway
      }, 1000);
      setTimeout(() => {
        addLog('info', '[Gateway] Packet received. Starting Fast-Fail verification pipeline.');
        addLog('info', '[Gateway] ✓ Step 1: Signature Header Present');
        addLog('info', '[Gateway] ✓ Step 2: Timestamp Range OK');
        addLog('info', '[Gateway] ✓ Step 3: Nonce Cache Verification OK');
        addLog('info', '[Gateway] ✓ Step 4: Payload Digest Match OK');
        addLog('info', '[Gateway] ✓ Step 5: ECDSA Math Verification OK');
        setPacketStage(3); // Move to Upstream
      }, 2000);
      setTimeout(() => {
        addLog('success', '[Upstream] [PASS] 200 OK - Request processed successfully.');
        setPacketStage(0);
        setIsSimulating(false);
      }, 3000);
      
    } else if (scenario === 'hijack') {
      setTimeout(() => {
        addLog('error', '[Network] Warning: Attacker intercepted JWT. Bypassing TPM hardware...');
        setPacketStage(2); // Move to Gateway directly (logically)
      }, 1000);
      setTimeout(() => {
        addLog('info', '[Gateway] Packet received. Starting Fast-Fail verification pipeline.');
        addLog('error', '[Gateway] ✗ Step 1: Signature Header Missing');
        setPacketStage(4); // Blocked at Gateway
      }, 2000);
      setTimeout(() => {
        addLog('error', '[Gateway] [BLOCKED] 401 Unauthorized - Session Hijacking Detected. Connection Terminated.');
        setPacketStage(0);
        setIsSimulating(false);
      }, 3500);
      
    } else if (scenario === 'replay') {
      setTimeout(() => {
        addLog('info', '[TPM] Hardware signing complete. (ECDSA P-256)');
        setPacketStage(2); // Move to Gateway
      }, 1000);
      setTimeout(() => {
        addLog('error', '[Network] Warning: Attacker is replaying a previously intercepted packet!');
        addLog('info', '[Gateway] Packet received. Starting Fast-Fail verification pipeline.');
        addLog('info', '[Gateway] ✓ Step 1: Signature Header Present');
        addLog('info', '[Gateway] ✓ Step 2: Timestamp Range OK');
        addLog('error', '[Gateway] ✗ Step 3: Nonce Already Consumed in Cache');
        setPacketStage(4); // Blocked at Gateway
      }, 2000);
      setTimeout(() => {
        addLog('error', '[Gateway] [BLOCKED] 401 Unauthorized - Replay Attack Detected. Connection Terminated.');
        setPacketStage(0);
        setIsSimulating(false);
      }, 3500);
      
    } else if (scenario === 'tamper') {
      setTimeout(() => {
        addLog('info', '[TPM] Hardware signing complete. (ECDSA P-256)');
        setPacketStage(2); // Move to Gateway
      }, 1000);
      setTimeout(() => {
        addLog('error', '[Network] Warning: Attacker modified the HTTP Body payload in transit!');
        addLog('info', '[Gateway] Packet received. Starting Fast-Fail verification pipeline.');
        addLog('info', '[Gateway] ✓ Step 1: Signature Header Present');
        addLog('info', '[Gateway] ✓ Step 2: Timestamp Range OK');
        addLog('info', '[Gateway] ✓ Step 3: Nonce Cache Verification OK');
        addLog('error', '[Gateway] ✗ Step 4: Payload Digest Mismatch (Body altered)');
        setPacketStage(4); // Blocked at Gateway
      }, 2000);
      setTimeout(() => {
        addLog('error', '[Gateway] [BLOCKED] 403 Forbidden - Payload Tampering Detected. Connection Terminated.');
        setPacketStage(0);
        setIsSimulating(false);
      }, 3500);
    }
  };

  // --- Chart Data ---
  const throughputData = [
    { name: 'Sync (O(N))', RPS: 145 },
    { name: 'Async (O(1))', RPS: 780 },
  ];
  
  const latencyData = [
    { name: 'Sync (O(N))', Latency: 1400 },
    { name: 'Async (O(1))', Latency: 78 },
  ];
  
  const payloadData = [
    { name: 'RSA-2048', value: 499 },
    { name: 'ECDSA P-256', value: 252 },
  ];
  const PIE_COLORS = ['#3b82f6', '#10b981'];
  
  return (
    <div className="min-h-screen bg-zinc-950 text-slate-200 p-4 sm:p-6 lg:p-8 font-sans selection:bg-cyan-900 selection:text-cyan-100 relative">
      
      {/* 1. Dashboard Header */}
      <header className="mb-8 border-b border-zinc-800 pb-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <Shield className="text-emerald-500" size={32} />
            FIDO2 PoP Gateway
          </h1>
          <p className="text-zinc-400 mt-2 text-sm tracking-wide">Live Security & Performance Telemetry</p>
        </div>
        
        {/* Paper Button */}
        <div className="flex items-center gap-4">
          <button 
            onClick={() => setIsPaperOpen(true)}
            className="group flex items-center gap-2 bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 transition-all px-5 py-2.5 rounded-lg text-sm font-medium shadow-sm"
          >
            <FileText className="text-blue-400" size={18} />
            <span className="text-zinc-200 group-hover:text-white">View Paper</span>
          </button>
        </div>
      </header>

      {/* Grid Layout Container */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* SECTION 1: Interactive Architecture Flow (Full Span) */}
        <div className="lg:col-span-12 bg-zinc-900/50 rounded-xl border border-zinc-800/80 p-4 sm:p-6 lg:p-8 shadow-2xl relative overflow-hidden backdrop-blur-sm">
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 mb-6 sm:mb-10">
            <h2 className="text-xl font-semibold text-white flex items-center gap-2">
              <Cpu className="text-cyan-500" size={20}/>
              Authentication Architecture
            </h2>
            <div className="text-xs sm:text-sm text-zinc-400 bg-zinc-950 px-3 py-1.5 sm:px-4 sm:py-2 rounded-lg border border-zinc-800">
              Select a scenario from the Attack Simulator below to animate the flow.
            </div>
          </div>
          
          <div className="w-full overflow-x-auto pb-4 pt-2 custom-scrollbar">
            <div className="relative flex justify-between items-center py-10 px-6 sm:px-12 lg:px-16 w-full min-w-[640px] max-w-5xl mx-auto">
              {/* Background Connection Line */}
              <div className="absolute top-1/2 left-16 right-16 h-[2px] bg-zinc-800 -translate-y-1/2 z-0"></div>
              
              {/* Nodes */}
              <Node icon={<Cpu size={28} />} title="Client Application" />
              <Node icon={<Lock size={28} />} title="FIDO2 TPM Hardware" active={packetStage === 1 || packetStage === 2} isError={packetStage > 0 && currentScenario !== 'normal'} />
              <Node icon={<Shield size={28} />} title="PoP Gateway" active={packetStage === 2 || packetStage === 3 || packetStage === 4} isGateway isError={packetStage === 4} />
              <Node icon={<Server size={28} />} title="Upstream Server" active={packetStage === 3} />

              {/* Animated Packet */}
              <AnimatePresence>
                {packetStage > 0 && packetStage < 4 && (
                  <motion.div
                    className="absolute top-1/2 -translate-y-1/2 z-20 flex flex-col items-center"
                    initial={{ left: '10%', opacity: 0 }}
                    animate={{ 
                      left: packetStage === 1 ? '38%' : packetStage === 2 ? '62%' : '88%',
                      opacity: 1
                    }}
                    exit={{ opacity: 0 }}
                    transition={{ duration: 0.8, ease: "easeInOut" }}
                  >
                    <div className={`text-xs font-bold px-3 py-1.5 rounded mb-3 whitespace-nowrap backdrop-blur-md border ${currentScenario === 'normal' ? 'bg-emerald-500/10 border-emerald-500/50 text-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.3)]' : 'bg-rose-500/10 border-rose-500/50 text-rose-400 shadow-[0_0_15px_rgba(244,63,94,0.3)]'}`}>
                      {currentScenario === 'normal' ? 'JWT + Nonce + ECDSA Sig' : 
                       currentScenario === 'hijack' ? 'JWT (Missing Sig)' :
                       currentScenario === 'replay' ? 'JWT + Used Nonce + Sig' :
                       'JWT + Modified Body + Sig'}
                    </div>
                    <div className={`w-4 h-4 rounded-full ${currentScenario === 'normal' ? 'bg-emerald-400 shadow-[0_0_20px_rgba(16,185,129,1)]' : 'bg-rose-500 shadow-[0_0_20px_rgba(244,63,94,1)]'}`}></div>
                  </motion.div>
                )}
                {/* Blocked Animation at Gateway */}
                {packetStage === 4 && (
                  <motion.div
                    className="absolute top-1/2 left-[62%] -translate-y-1/2 z-20 flex flex-col items-center"
                    initial={{ scale: 0.5, opacity: 0 }}
                    animate={{ scale: [1, 1.3, 1], opacity: 1 }}
                    exit={{ opacity: 0, scale: 0 }}
                    transition={{ duration: 0.4 }}
                  >
                    <div className="bg-rose-500/20 border border-rose-500/50 text-rose-400 text-xs font-bold px-3 py-1.5 rounded shadow-[0_0_15px_rgba(244,63,94,0.3)] mb-3 whitespace-nowrap backdrop-blur-md">
                      Connection Terminated
                    </div>
                    <XOctagon className="text-rose-500 drop-shadow-[0_0_20px_rgba(244,63,94,1)]" size={32} />
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </div>
          {/* Mobile scroll hint */}
          <div className="sm:hidden text-center text-xs text-zinc-500 mt-1 flex items-center justify-center gap-1">
            <span>↔ 좌우로 스크롤하여 전체 아키텍처 흐름 확인</span>
          </div>
        </div>

        {/* SECTION 2: Attack Simulator & Fast-Fail Log */}
        <div className="lg:col-span-6 bg-zinc-900/50 rounded-xl border border-zinc-800/80 p-4 sm:p-6 shadow-2xl flex flex-col min-h-[480px] lg:h-[500px]">
          <h2 className="text-xl font-semibold text-white flex items-center gap-2 mb-2">
            <AlertTriangle className="text-rose-500" size={20}/>
            Attack Simulator & Fast-Fail Funnel
          </h2>
          <p className="text-sm text-zinc-400 mb-6">
            Click a scenario to visualize how the Gateway intercepts malicious requests.
          </p>
          
          <div className="grid grid-cols-2 gap-3 mb-6">
            <AttackButton 
              title="Normal Request" 
              desc="Valid Signature & Nonce"
              color="emerald" 
              disabled={isSimulating}
              onClick={() => runSimulation('normal')} 
            />
            <AttackButton 
              title="Session Hijacking" 
              desc="Missing PoP Signature"
              color="rose" 
              disabled={isSimulating}
              onClick={() => runSimulation('hijack')} 
            />
            <AttackButton 
              title="Replay Attack" 
              desc="Previously Used Nonce"
              color="rose" 
              disabled={isSimulating}
              onClick={() => runSimulation('replay')} 
            />
            <AttackButton 
              title="Tampering" 
              desc="Modified Payload Body"
              color="rose" 
              disabled={isSimulating}
              onClick={() => runSimulation('tamper')} 
            />
          </div>

          <div className="flex-1 bg-black/80 rounded-lg border border-zinc-800 p-4 font-mono text-sm overflow-hidden flex flex-col relative shadow-inner">
            <div className="flex items-center gap-2 text-zinc-500 mb-3 pb-3 border-b border-zinc-900">
              <Terminal size={14} /> <span>Gateway Terminal / Server Log</span>
            </div>
            <div className="flex-1 overflow-y-auto pr-2 scroll-smooth">
              {logs.length === 0 && <span className="text-zinc-600 italic">Waiting for incoming requests...</span>}
              <AnimatePresence initial={false}>
                {logs.map(log => (
                  <motion.div 
                    key={log.id} 
                    initial={{ opacity: 0, x: -10 }} 
                    animate={{ opacity: 1, x: 0 }}
                    className={`mb-2 font-medium ${log.type === 'success' ? 'text-emerald-400' : log.type === 'error' ? 'text-rose-500' : 'text-cyan-400'}`}
                  >
                    <span className="text-zinc-600 mr-3">[{log.time}]</span>
                    {log.message}
                  </motion.div>
                ))}
              </AnimatePresence>
              <div ref={logsEndRef} />
            </div>
          </div>
        </div>

        {/* SECTIONS 3 & 4: Performance & Payload Metrics */}
        <div className="lg:col-span-6 flex flex-col gap-6 min-h-[500px] lg:h-[500px]">
          
          <div className="bg-zinc-900/50 rounded-xl border border-zinc-800/80 p-4 sm:p-6 shadow-2xl flex-1 flex flex-col">
             <h2 className="text-xl font-semibold text-white flex items-center gap-2 mb-4">
              <Activity className="text-cyan-500" size={20}/>
              Concurrency Optimization
            </h2>
            <div className="flex-1 grid grid-cols-1 sm:grid-cols-2 gap-6 min-h-[300px] sm:min-h-0">
              
              <div className="h-full flex flex-col">
                <h3 className="text-xs text-zinc-400 text-center mb-4 tracking-wider font-semibold">
                  Throughput (RPS) <span className="text-emerald-400 ml-1 bg-emerald-500/10 px-2 py-0.5 rounded">+437%</span>
                </h3>
                <div className="flex-1 min-h-0">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={throughputData} margin={{ top: 0, right: 0, left: -25, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#27272a" vertical={false} />
                      <XAxis dataKey="name" stroke="#a1a1aa" fontSize={11} tickLine={false} axisLine={false} />
                      <YAxis stroke="#a1a1aa" fontSize={11} tickLine={false} axisLine={false} />
                      <RechartsTooltip cursor={{fill: '#27272a'}} contentStyle={{backgroundColor: '#09090b', borderColor: '#27272a', color: '#fff', borderRadius: '8px'}} />
                      <Bar dataKey="RPS" fill="#10b981" radius={[4, 4, 0, 0]} barSize={40} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>

              <div className="h-full flex flex-col">
                <h3 className="text-xs text-zinc-400 text-center mb-4 tracking-wider font-semibold">
                  P95 Latency (ms) <span className="text-cyan-400 ml-1 bg-cyan-500/10 px-2 py-0.5 rounded">-94%</span>
                </h3>
                <div className="flex-1 min-h-0">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={latencyData} margin={{ top: 0, right: 0, left: -10, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#27272a" vertical={false} />
                      <XAxis dataKey="name" stroke="#a1a1aa" fontSize={11} tickLine={false} axisLine={false} />
                      <YAxis stroke="#a1a1aa" fontSize={11} tickLine={false} axisLine={false} />
                      <RechartsTooltip cursor={{fill: '#27272a'}} contentStyle={{backgroundColor: '#09090b', borderColor: '#27272a', color: '#fff', borderRadius: '8px'}} />
                      <Bar dataKey="Latency" fill="#0ea5e9" radius={[4, 4, 0, 0]} barSize={40} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>

            </div>
          </div>

          <div className="bg-zinc-900/50 rounded-xl border border-zinc-800/80 p-5 shadow-2xl h-[170px] flex flex-col justify-center">
            <div className="flex justify-between items-start mb-2">
              <h2 className="text-lg font-semibold text-white flex items-center gap-2">
                <Lock className="text-purple-500" size={18}/>
                Header Payload Overhead
              </h2>
            </div>
            
            <div className="flex items-center flex-1">
              <div className="w-[120px] h-full">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={payloadData}
                      cx="50%"
                      cy="50%"
                      innerRadius={30}
                      outerRadius={45}
                      paddingAngle={5}
                      dataKey="value"
                      stroke="none"
                    >
                      {payloadData.map((_, index) => (
                        <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                      ))}
                    </Pie>
                    <RechartsTooltip contentStyle={{backgroundColor: '#09090b', borderColor: '#27272a', color: '#fff', borderRadius: '8px', padding: '4px 8px'}} itemStyle={{fontSize: '12px'}} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              
              <div className="flex-1 pl-4 flex flex-col justify-center">
                <div className="flex gap-6 mb-3">
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded bg-blue-500"></div>
                    <div>
                      <div className="text-sm font-medium text-white leading-tight">RSA-2048</div>
                      <div className="text-xs text-zinc-400">499 Bytes</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded bg-emerald-500"></div>
                    <div>
                      <div className="text-sm font-medium text-white leading-tight">ECDSA P-256</div>
                      <div className="text-xs text-zinc-400">252 Bytes</div>
                    </div>
                  </div>
                </div>
                <p className="text-xs text-zinc-400 bg-zinc-950/80 py-2 px-3 rounded-md border border-zinc-800/80 inline-block">
                  <span className="text-emerald-400 font-semibold mr-1">50% bandwidth reduction</span> 
                  for constrained hardware environments.
                </p>
              </div>
            </div>
          </div>

        </div>
      </div>

      {/* PAPER MODAL OVERLAY */}
      <AnimatePresence>
        {isPaperOpen && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm"
            onClick={() => setIsPaperOpen(false)}
          >
            <motion.div 
              initial={{ y: 50, opacity: 0, scale: 0.95 }}
              animate={{ y: 0, opacity: 1, scale: 1 }}
              exit={{ y: 20, opacity: 0, scale: 0.95 }}
              transition={{ type: 'spring', damping: 25, stiffness: 300 }}
              onClick={(e) => e.stopPropagation()}
              className="bg-zinc-950 border border-zinc-800 rounded-xl shadow-2xl w-full max-w-4xl max-h-[90vh] flex flex-col overflow-hidden relative"
            >
              <div className="flex items-center justify-between p-4 border-b border-zinc-800 bg-zinc-900/50">
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  <FileText className="text-blue-400" size={20} />
                  FIDO2 PoP Gateway {paperLang === 'ko' ? '논문' : 'Paper'}
                </h3>
                <div className="flex items-center gap-4">
                  <div className="flex bg-zinc-950 border border-zinc-700 rounded-lg overflow-hidden p-0.5">
                    <button 
                      onClick={() => setPaperLang('ko')}
                      className={`px-3 py-1 text-xs font-medium rounded-md transition-colors ${paperLang === 'ko' ? 'bg-zinc-800 text-white' : 'text-zinc-500 hover:text-zinc-300'}`}
                    >
                      🇰🇷 KO
                    </button>
                    <button 
                      onClick={() => setPaperLang('en')}
                      className={`px-3 py-1 text-xs font-medium rounded-md transition-colors ${paperLang === 'en' ? 'bg-zinc-800 text-white' : 'text-zinc-500 hover:text-zinc-300'}`}
                    >
                      🇺🇸 EN
                    </button>
                  </div>
                  <button 
                    onClick={() => setIsPaperOpen(false)}
                    className="p-1.5 hover:bg-zinc-800 rounded-lg text-zinc-400 hover:text-white transition-colors"
                  >
                    <X size={20} />
                  </button>
                </div>
              </div>
              
              <div className="flex-1 overflow-y-auto p-4 sm:p-8 custom-scrollbar bg-zinc-950">
                {paperContent ? (
                  <div className="prose prose-invert prose-zinc max-w-none prose-headings:text-zinc-100 prose-a:text-blue-400 prose-strong:text-zinc-200">
                    <ReactMarkdown 
                      remarkPlugins={[remarkGfm, remarkMath]}
                      rehypePlugins={[rehypeKatex]}
                      components={{
                        img: ({ ...props }) => {
                          let src = props.src || '';
                          if (src.startsWith('../img/')) {
                            src = src.replace('../img/', './img/');
                          }
                          return <img {...props} src={src} className="rounded-lg max-w-full my-6 border border-zinc-800 shadow-md" alt={props.alt || ''} />;
                        }
                      }}
                    >
                      {paperContent}
                    </ReactMarkdown>
                  </div>
                ) : (
                  <div className="flex items-center justify-center h-full text-zinc-500">
                    Loading paper content...
                  </div>
                )}
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

// --- Helper Components ---

const Node = ({ icon, title, active, isGateway = false, isError = false }: { icon: React.ReactNode, title: string, active?: boolean, isGateway?: boolean, isError?: boolean }) => (
  <div className={`relative z-10 flex-shrink-0 flex flex-col items-center justify-center w-24 h-24 sm:w-28 sm:h-28 rounded-2xl border-2 transition-all duration-500 bg-zinc-950 
    ${active && !isGateway && !isError ? 'border-cyan-500 shadow-[0_0_25px_rgba(6,182,212,0.4)] transform scale-105' : ''}
    ${active && isGateway && !isError ? 'border-emerald-500 shadow-[0_0_25px_rgba(16,185,129,0.4)] transform scale-105' : ''}
    ${isError ? 'border-rose-500 shadow-[0_0_25px_rgba(244,63,94,0.4)] transform scale-105' : ''}
    ${!active && !isError ? 'border-zinc-800' : ''}
  `}>
    <div className={`mb-2 sm:mb-3 transition-colors duration-500 
      ${active && !isGateway && !isError ? 'text-cyan-400' : ''} 
      ${active && isGateway && !isError ? 'text-emerald-400' : ''} 
      ${isError ? 'text-rose-500' : ''}
      ${!active && !isError ? 'text-zinc-500' : ''}
    `}>
      {icon}
    </div>
    <span className={`text-[11px] sm:text-xs font-semibold text-center leading-tight px-2 
      ${active || isError ? 'text-white' : 'text-zinc-400'}
    `}>
      {title}
    </span>
  </div>
);

const AttackButton = ({ title, desc, color, disabled, onClick }: { title: string, desc: string, color: 'emerald' | 'rose', disabled: boolean, onClick: () => void }) => {
  const colorMap = {
    emerald: 'hover:bg-emerald-500/10 border-emerald-500/30 text-emerald-400 hover:border-emerald-500 hover:shadow-[0_0_15px_rgba(16,185,129,0.2)]',
    rose: 'hover:bg-rose-500/10 border-rose-500/30 text-rose-400 hover:border-rose-500 hover:shadow-[0_0_15px_rgba(244,63,94,0.2)]'
  };
  
  return (
    <button 
      onClick={onClick}
      disabled={disabled}
      className={`flex flex-col items-start p-3.5 rounded-lg border transition-all duration-200 text-left bg-zinc-950/80 
      ${disabled ? 'opacity-50 cursor-not-allowed border-zinc-800' : `${colorMap[color]} group`}`}
    >
      <span className="font-semibold text-sm group-hover:text-white transition-colors">{title}</span>
      <span className="text-xs opacity-70 mt-1">{desc}</span>
    </button>
  );
};

export default Dashboard;
