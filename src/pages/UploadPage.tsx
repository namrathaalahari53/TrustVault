import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { api } from '../services/api';
import { Upload, FileText, CheckCircle, AlertCircle, ArrowLeft, Shield } from 'lucide-react';

export const UploadPage: React.FC = () => {
  const { navigateTo, showToast } = useAuth();
  const [file, setFile] = useState<File | null>(null);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [category, setCategory] = useState('Compliance & Security');
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const selected = e.target.files[0];
      setFile(selected);
      setError(null);
      if (!title) {
        setTitle(selected.name.replace(/\.[^/.]+$/, '').replace(/[_-]/g, ' '));
      }
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) {
      setError('Please select a document file to upload.');
      return;
    }

    if (!title.trim()) {
      setError('Please provide a document title.');
      return;
    }

    setIsUploading(true);
    setError(null);

    const formData = new FormData();
    formData.append('file', file);
    formData.append('title', title.trim());
    formData.append('description', description.trim());
    formData.append('category', category);

    try {
      const result = await api.uploadDocument(formData);
      showToast('success', 'Upload Succeeded', `Encrypted and stored "${result.document.title}"`);
      navigateTo('document-detail', result.document.id);
    } catch (err: any) {
      setError(err.message || 'File upload failed. Ensure magic bytes and file size match security policy.');
      showToast('error', 'Upload Denied', err.message);
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <div className="flex items-center gap-3 pb-4 border-b border-slate-800">
        <button
          onClick={() => navigateTo('repository')}
          className="text-xs text-slate-400 hover:text-white flex items-center gap-1.5 transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Repository</span>
        </button>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 sm:p-8 shadow-xl space-y-6">
        <div>
          <h2 className="text-lg font-bold text-white tracking-tight">Upload Confidential Document</h2>
          <p className="text-xs text-slate-400 mt-1">
            Documents are validated against binary signatures, assigned random storage identifiers, and stored outside static web roots.
          </p>
        </div>

        {error && (
          <div className="p-3.5 rounded-lg bg-rose-950/60 border border-rose-800 text-xs text-rose-200 flex items-start gap-2.5">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              Document File (PDF, DOCX, TXT, CSV, XLSX, PNG, JPG)
            </label>
            <div className="border-2 border-dashed border-slate-700 hover:border-blue-500/70 rounded-lg p-6 text-center transition-colors bg-slate-950/60">
              <input
                type="file"
                id="file-upload"
                className="hidden"
                onChange={handleFileChange}
                accept=".pdf,.doc,.docx,.txt,.csv,.xlsx,.png,.jpg,.jpeg"
              />
              <label htmlFor="file-upload" className="cursor-pointer flex flex-col items-center">
                <Upload className="w-8 h-8 text-blue-400 mb-2" />
                <span className="text-xs font-semibold text-white">
                  {file ? file.name : 'Click to select or drag and drop document'}
                </span>
                <span className="text-[11px] text-slate-500 mt-1 font-mono">
                  {file ? `${(file.size / 1024).toFixed(1)} KB` : 'Maximum file size: 50MB · Magic bytes inspected'}
                </span>
              </label>
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">Document Title</label>
            <input
              type="text"
              required
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="e.g. Q4 SOC 2 Type II System Security Plan"
              className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-md text-xs text-white focus:outline-none focus:border-blue-500"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">Category</label>
            <select
              value={category}
              onChange={(e) => setCategory(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-md text-xs text-white focus:outline-none focus:border-blue-500"
            >
              <option value="Compliance & Security">Compliance & Security</option>
              <option value="Finance & Risk">Finance & Risk</option>
              <option value="Legal">Legal</option>
              <option value="General">General</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">Description (Optional)</label>
            <textarea
              rows={3}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Scope, sensitivity classification, and relevant stakeholders..."
              className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-md text-xs text-white focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="pt-2">
            <button
              type="submit"
              disabled={isUploading}
              className="w-full flex justify-center items-center gap-2 py-2.5 px-4 rounded-md shadow-sm text-xs font-medium text-white bg-blue-600 hover:bg-blue-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 transition-colors"
            >
              <Shield className="w-3.5 h-3.5" />
              <span>{isUploading ? 'Validating Magic Bytes & Encrypting...' : 'Secure & Upload Document'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
