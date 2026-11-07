import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { api } from '../services/api';
import { DocumentItem } from '../types';
import {
  Search,
  Filter,
  FileText,
  Download,
  Eye,
  Trash2,
  Share2,
  Upload,
  Lock,
  Unlock,
  Shield,
  Clock,
  HardDrive,
  User,
  AlertCircle,
  ExternalLink,
} from 'lucide-react';

export const RepositoryPage: React.FC = () => {
  const { user, isOwner, isAdmin, navigateTo, showToast } = useAuth();
  const [documents, setDocuments] = useState<DocumentItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [search, setSearch] = useState<string>('');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [downloadingId, setDownloadingId] = useState<string | null>(null);

  const fetchDocuments = async () => {
    setLoading(true);
    try {
      const data = await api.listDocuments({
        search: search || undefined,
        category: selectedCategory !== 'ALL' ? selectedCategory : undefined,
      });
      setDocuments(data.documents);
    } catch (err: any) {
      showToast('error', 'Failed to load documents', err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDocuments();
  }, [search, selectedCategory]);

  const handleDownload = async (doc: DocumentItem) => {
    setDownloadingId(doc.id);
    try {
      await api.downloadDocument(doc.id, doc.original_filename);
      showToast('success', 'Download Started', `Downloading ${doc.original_filename}`);
    } catch (err: any) {
      showToast('error', 'Access Denied', err.message || 'You do not have permission to download this document.');
    } finally {
      setDownloadingId(null);
    }
  };

  const handleDelete = async (doc: DocumentItem) => {
    if (!window.confirm(`Are you sure you want to delete "${doc.title}"? This action is audited.`)) {
      return;
    }

    try {
      await api.deleteDocument(doc.id);
      showToast('success', 'Document Deleted', 'Document successfully archived and deleted.');
      fetchDocuments();
    } catch (err: any) {
      showToast('error', 'Delete Denied', err.message || 'Only document owners can delete documents.');
    }
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const formatDate = (isoString: string): string => {
    const d = new Date(isoString);
    return d.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  };

  const categories = ['ALL', 'Compliance & Security', 'Finance & Risk', 'Legal', 'General'];

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">Secure Document Repository</h1>
          <p className="text-xs text-slate-400 mt-1">
            Zero-trust repository with strict object-level access verification and immediate revocation.
          </p>
        </div>
        {(isOwner || isAdmin) && (
          <button
            onClick={() => navigateTo('upload')}
            className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-white bg-blue-600 rounded-md hover:bg-blue-500 transition-colors shadow-sm self-start sm:self-auto"
          >
            <Upload className="w-3.5 h-3.5" />
            <span>Upload New Document</span>
          </button>
        )}
      </div>

      {/* Filters & Search */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
            <Search className="w-4 h-4" />
          </div>
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search documents by title, description or filename..."
            className="block w-full pl-9 pr-3 py-2 bg-slate-900 border border-slate-800 rounded-md text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          />
        </div>

        {/* Interactive Segmented Filter (Button element per frontend guidelines) */}
        <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg overflow-x-auto">
          {categories.map((cat) => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap transition-colors ${
                selectedCategory === cat
                  ? 'bg-slate-800 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      {/* Document Grid / Table */}
      {loading ? (
        <div className="p-12 text-center text-xs text-slate-500">
          <div className="inline-block animate-spin rounded-full h-6 w-6 border-2 border-blue-500 border-t-transparent mb-2"></div>
          <div>Loading encrypted repository index...</div>
        </div>
      ) : documents.length === 0 ? (
        <div className="p-12 text-center bg-slate-900/50 border border-slate-800 rounded-xl">
          <FileText className="w-10 h-10 text-slate-600 mx-auto mb-3" />
          <h3 className="text-sm font-semibold text-slate-300">No Accessible Documents</h3>
          <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
            {search || selectedCategory !== 'ALL'
              ? 'No documents matched your active search filters.'
              : 'You do not currently own or have shared access to any documents in this vault.'}
          </p>
          {(isOwner || isAdmin) && (
            <button
              onClick={() => navigateTo('upload')}
              className="mt-4 px-3.5 py-1.5 text-xs font-medium text-white bg-blue-600 rounded-md hover:bg-blue-500 transition-colors"
            >
              Upload First Document
            </button>
          )}
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-3">
          {documents.map((doc) => {
            const hasRead = doc.is_owner || doc.user_permission === 'READ' || doc.user_permission === 'EDIT';
            const hasEdit = doc.is_owner || doc.user_permission === 'EDIT';

            return (
              <div
                key={doc.id}
                className="bg-slate-900/90 border border-slate-800 hover:border-slate-700/80 rounded-lg p-4 transition-all duration-150 flex flex-col md:flex-row md:items-center justify-between gap-4"
              >
                <div className="space-y-1.5 flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <button
                      onClick={() => navigateTo('document-detail', doc.id)}
                      className="text-sm font-semibold text-white hover:text-blue-400 transition-colors truncate text-left"
                    >
                      {doc.title}
                    </button>

                    {/* Unboxed text metadata with clean separators per anti-slop guidelines */}
                    <div className="flex items-center gap-1.5 text-xs text-slate-400 font-mono">
                      <span>·</span>
                      <span
                        className={
                          doc.is_owner
                            ? 'text-blue-400 font-medium'
                            : doc.user_permission === 'EDIT'
                            ? 'text-amber-400 font-medium'
                            : doc.user_permission === 'READ'
                            ? 'text-emerald-400 font-medium'
                            : 'text-slate-500'
                        }
                      >
                        {doc.is_owner
                          ? 'OWNER'
                          : doc.user_permission === 'EDIT'
                          ? 'EDIT PERMITTED'
                          : doc.user_permission === 'READ'
                          ? 'READ PERMITTED'
                          : doc.user_permission}
                      </span>
                      <span>·</span>
                      <span>{doc.category}</span>
                    </div>
                  </div>

                  <p className="text-xs text-slate-400 line-clamp-1">{doc.description || 'No description provided.'}</p>

                  {/* Clean unboxed metadata footer */}
                  <div className="flex items-center gap-2 text-xs text-slate-500 flex-wrap">
                    <span>File: <span className="font-mono text-slate-400">{doc.original_filename}</span></span>
                    <span aria-hidden="true">·</span>
                    <span className="font-mono tabular-nums">{formatFileSize(doc.file_size)}</span>
                    <span aria-hidden="true">·</span>
                    <span>Owner: {doc.owner_name} ({doc.owner_email})</span>
                    <span aria-hidden="true">·</span>
                    <span>Uploaded {formatDate(doc.created_at)}</span>
                  </div>
                </div>

                {/* Actions */}
                <div className="flex items-center gap-2 shrink-0 pt-2 md:pt-0 border-t md:border-t-0 border-slate-800">
                  <button
                    onClick={() => navigateTo('document-detail', doc.id)}
                    className="px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium flex items-center gap-1.5 transition-colors"
                    title="View Document Details"
                  >
                    <Eye className="w-3.5 h-3.5 text-slate-400" />
                    <span>Inspect</span>
                  </button>

                  <button
                    onClick={() => handleDownload(doc)}
                    disabled={downloadingId === doc.id || !hasRead}
                    className={`px-2.5 py-1.5 rounded text-xs font-medium flex items-center gap-1.5 transition-colors ${
                      hasRead
                        ? 'bg-blue-600/15 hover:bg-blue-600/25 text-blue-300 border border-blue-500/30'
                        : 'bg-slate-800/40 text-slate-500 cursor-not-allowed border border-slate-800'
                    }`}
                    title={hasRead ? 'Download File' : 'Permission Required to Download'}
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>{downloadingId === doc.id ? 'Streaming...' : 'Download'}</span>
                  </button>

                  {doc.is_owner && (
                    <>
                      <button
                        onClick={() => navigateTo('access-management', doc.id)}
                        className="px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium flex items-center gap-1.5 transition-colors"
                        title="Manage Permissions & Share"
                      >
                        <Share2 className="w-3.5 h-3.5 text-slate-400" />
                        <span>Access</span>
                      </button>

                      <button
                        onClick={() => handleDelete(doc)}
                        className="p-1.5 rounded bg-slate-800 hover:bg-rose-950 hover:text-rose-400 text-slate-400 transition-colors"
                        title="Delete Document"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
