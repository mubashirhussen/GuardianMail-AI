import React, { useState, useEffect } from 'react';
import { Shield, Send, Plus, Trash2, Cpu, Info } from 'lucide-react';

interface Conversation {
  _id: string;
  title: string;
  created_at: string;
  updated_at: string;
}

interface Message {
  _id?: string;
  role: string;
  content: string;
  sources?: any[];
  created_at: string;
}

export const CopilotChat: React.FC = () => {
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [activeConvId, setActiveConvId] = useState<string | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [listLoading, setListLoading] = useState(false);

  useEffect(() => {
    fetchConversations();
  }, []);

  useEffect(() => {
    if (activeConvId) {
      fetchMessages(activeConvId);
    } else {
      setMessages([]);
    }
  }, [activeConvId]);

  const fetchConversations = async () => {
    setListLoading(true);
    try {
      const token = localStorage.getItem('token');
      const res = await fetch('/api/v1/copilot/conversations', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        setConversations(await res.json());
      }
    } catch (e) {
      console.error(e);
    }
    setListLoading(false);
  };

  const fetchMessages = async (convId: string) => {
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`/api/v1/copilot/conversations/${convId}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        setMessages(await res.json());
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleStartNewChat = () => {
    setActiveConvId(null);
    setMessages([]);
    setInput('');
  };

  const handleSendMessage = async (textToSend?: string) => {
    const queryText = textToSend || input;
    if (!queryText.trim()) return;

    setLoading(true);
    if (!textToSend) setInput('');

    // Pre-insert user message locally
    const userMsg: Message = {
      role: 'user',
      content: queryText,
      created_at: new Date().toISOString()
    };
    setMessages((prev) => [...prev, userMsg]);

    try {
      const token = localStorage.getItem('token');
      const res = await fetch('/api/v1/copilot/chat', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          conversation_id: activeConvId,
          query: queryText
        })
      });

      if (res.ok) {
        const data = await res.json();
        // If it was a new conversation, set active ID and reload list
        if (!activeConvId && data.conversation_id) {
          setActiveConvId(data.conversation_id);
          fetchConversations();
        }
        
        const assistantMsg: Message = {
          role: 'assistant',
          content: data.content,
          sources: data.sources || [],
          created_at: new Date().toISOString()
        };
        setMessages((prev) => [...prev, assistantMsg]);
      }
    } catch (e) {
      console.error(e);
    }
    setLoading(false);
  };

  const handleDeleteConversation = async (convId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!window.confirm("Are you sure you want to delete this chat history?")) return;

    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`/api/v1/copilot/conversations/${convId}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        if (activeConvId === convId) {
          setActiveConvId(null);
          setMessages([]);
        }
        fetchConversations();
      }
    } catch (e) {
      console.error(e);
    }
  };

  const suggestions = [
    "Explain latest domain threat rules",
    "List high risk indicators seen this week",
    "Summarize campaign tags correlation rules"
  ];

  return (
    <div className="h-[calc(100vh-6rem)] max-w-7xl mx-auto p-4 md:p-6 flex flex-col md:flex-row gap-6 text-left">
      
      {/* Sidebar: Conversation history */}
      <aside className="w-full md:w-80 bg-slate-900 border border-slate-800 rounded-2xl flex flex-col overflow-hidden shrink-0">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <h3 className="font-bold text-slate-200 text-sm flex items-center gap-2">
            <Cpu className="h-4 w-4 text-cyan-400" />
            Copilot Sessions
          </h3>
          <button 
            onClick={handleStartNewChat}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 transition"
            title="Start New Chat"
          >
            <Plus className="h-4 w-4" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-2 space-y-1">
          {listLoading ? (
            <div className="text-center text-xs text-slate-500 py-8">Loading history...</div>
          ) : conversations.length === 0 ? (
            <div className="text-center text-xs text-slate-500 py-8">No previous chats.</div>
          ) : (
            conversations.map((conv) => (
              <div
                key={conv._id}
                onClick={() => setActiveConvId(conv._id)}
                className={`w-full p-3 rounded-xl border text-left text-xs transition cursor-pointer flex items-center justify-between gap-3 ${
                  activeConvId === conv._id
                    ? 'bg-cyan-500/10 border-cyan-500/40 text-cyan-400 font-semibold'
                    : 'bg-transparent border-transparent text-slate-400 hover:bg-slate-800/40 hover:text-slate-200'
                }`}
              >
                <span className="truncate max-w-[180px]">{conv.title}</span>
                <button
                  onClick={(e) => handleDeleteConversation(conv._id, e)}
                  className="text-slate-500 hover:text-red-400 p-0.5 rounded transition"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
            ))
          )}
        </div>
      </aside>

      {/* Main Chat Panel */}
      <main className="flex-1 bg-slate-900 border border-slate-800 rounded-2xl flex flex-col overflow-hidden">
        {/* Header */}
        <header className="p-4 border-b border-slate-800 flex items-center gap-3 bg-slate-950/30">
          <Shield className="h-5 w-5 text-cyan-400 animate-pulse" />
          <div>
            <h4 className="font-bold text-slate-200 text-sm">Security Copilot Terminal</h4>
            <p className="text-[10px] text-slate-500">Multitasking Security Agent grounded in local threat history</p>
          </div>
        </header>

        {/* Messages */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4 font-sans">
          {messages.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-center p-8 max-w-md mx-auto space-y-4">
              <div className="h-12 w-12 rounded-full bg-cyan-500/10 flex items-center justify-center text-cyan-400">
                <Shield className="h-6 w-6" />
              </div>
              <div>
                <h4 className="font-bold text-slate-200 text-sm">How can I assist your investigation?</h4>
                <p className="text-xs text-slate-500 mt-1 leading-relaxed">
                  I can summarize campaigns tags, list active policy parameters, identify homograph domain spoofs, or fetch reputational metrics.
                </p>
              </div>
              <div className="w-full pt-4 space-y-2">
                {suggestions.map((sug, i) => (
                  <button
                    key={i}
                    onClick={() => handleSendMessage(sug)}
                    className="w-full p-2.5 rounded-lg bg-slate-950 hover:bg-slate-800 text-left text-xs text-slate-400 border border-slate-800 hover:border-slate-700 transition"
                  >
                    {sug}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            messages.map((msg, idx) => (
              <div 
                key={idx} 
                className={`flex gap-3 max-w-3xl ${msg.role === 'user' ? 'ml-auto flex-row-reverse' : 'mr-auto'}`}
              >
                {/* Icon */}
                <div className={`h-8 w-8 rounded-full shrink-0 flex items-center justify-center font-bold text-xs ${
                  msg.role === 'user' ? 'bg-cyan-600 text-slate-950' : 'bg-slate-800 text-cyan-400 border border-slate-700'
                }`}>
                  {msg.role === 'user' ? 'U' : 'AI'}
                </div>

                {/* Text body */}
                <div className="space-y-2">
                  <div className={`p-4 rounded-2xl text-sm leading-relaxed border ${
                    msg.role === 'user'
                      ? 'bg-cyan-500/10 border-cyan-500/20 text-cyan-200'
                      : 'bg-slate-950/40 border-slate-800/80 text-slate-300'
                  }`}>
                    <p className="whitespace-pre-wrap">{msg.content}</p>
                  </div>
                  
                  {/* Citations Card */}
                  {msg.sources && msg.sources.length > 0 && (
                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-500 space-y-1 max-w-md">
                      <p className="font-semibold text-slate-400 flex items-center gap-1.5">
                        <Info className="h-3.5 w-3.5 text-cyan-400" />
                        Grounded Sources Cited
                      </p>
                      {msg.sources.map((src, si) => (
                        <div key={si} className="pl-5 font-mono text-[10px]">
                          - {src.title}: <span className="text-slate-400">{src.details?.join(', ')}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ))
          )}
          
          {loading && (
            <div className="flex gap-3 mr-auto">
              <div className="h-8 w-8 rounded-full bg-slate-800 border border-slate-700 text-cyan-400 flex items-center justify-center animate-spin">
                <Shield className="h-4 w-4" />
              </div>
              <div className="py-2.5 text-xs text-slate-500 font-mono">
                Copilot is executing security reasoning checks...
              </div>
            </div>
          )}
        </div>

        {/* Input Bar */}
        <footer className="p-4 border-t border-slate-800 bg-slate-950/20">
          <div className="flex gap-2">
            <input
              type="text"
              placeholder="Ask Copilot a security question or paste an incident ID..."
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSendMessage()}
              disabled={loading}
              className="flex-1 bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
            />
            <button
              onClick={() => handleSendMessage()}
              disabled={loading || !input.trim()}
              className="px-4 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 disabled:text-slate-600 text-slate-950 font-bold transition flex items-center gap-2"
            >
              <Send className="h-4 w-4" />
              Send
            </button>
          </div>
        </footer>
      </main>
    </div>
  );
};
