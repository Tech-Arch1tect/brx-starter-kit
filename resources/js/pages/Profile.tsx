import { useState, useEffect } from 'react';
import Layout from '../components/Layout';
import { Head, Link, useForm } from '@inertiajs/react';
import { FlashMessage, User } from '../types';

interface ProfileProps {
  title: string;
  user: User;
  flash?: FlashMessage;
  csrfToken?: string;
}

export default function Profile({ title, user, flash, csrfToken }: ProfileProps) {
  const [totpEnabled, setTotpEnabled] = useState<boolean | null>(null);
  const [showDisableForm, setShowDisableForm] = useState(false);
  const { post, processing } = useForm();
  const {
    data: disableData,
    setData: setDisableData,
    post: postDisable,
    processing: disableProcessing,
  } = useForm({
    password: '',
    code: '',
  });

  useEffect(() => {
    // Fetch TOTP status
    fetch('/api/totp/status')
      .then((response) => response.json())
      .then((data) => setTotpEnabled(data.enabled))
      .catch((error) => console.error('Failed to fetch TOTP status:', error));
  }, []);

  const disableTOTP = (e: React.FormEvent) => {
    e.preventDefault();
    postDisable('/auth/totp/disable', {
      headers: {
        'X-CSRF-Token': csrfToken || '',
      },
      onSuccess: () => {
        setShowDisableForm(false);
        setDisableData({ password: '', code: '' });
        setTotpEnabled(false);
      },
    });
  };

  return (
    <Layout>
      <Head title={title} />
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="py-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-8">Profile</h1>

          {flash && (
            <div
              className={`mb-6 p-4 text-sm rounded-lg ${
                flash.type === 'success'
                  ? 'text-green-700 bg-green-100 border border-green-200'
                  : flash.type === 'error'
                    ? 'text-red-700 bg-red-100 border border-red-200'
                    : flash.type === 'warning'
                      ? 'text-yellow-700 bg-yellow-100 border border-yellow-200'
                      : 'text-blue-700 bg-blue-100 border border-blue-200'
              }`}
            >
              {flash.message}
            </div>
          )}

          <div className="space-y-6">
            {/* User Information */}
            <div className="bg-white shadow rounded-lg">
              <div className="px-6 py-4 border-b border-gray-200">
                <h2 className="text-lg font-semibold text-gray-800">User Information</h2>
              </div>
              <div className="px-6 py-4 space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700">Username</label>
                    <div className="mt-1 p-2 bg-gray-50 rounded-md">
                      <span className="text-gray-900">{user.username}</span>
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700">Email</label>
                    <div className="mt-1 p-2 bg-gray-50 rounded-md">
                      <span className="text-gray-900">{user.email}</span>
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700">Member since</label>
                    <div className="mt-1 p-2 bg-gray-50 rounded-md">
                      <span className="text-gray-900">
                        {new Date(user.CreatedAt).toLocaleDateString('en-GB', {
                          year: 'numeric',
                          month: 'long',
                          day: 'numeric',
                        })}
                      </span>
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700">Last updated</label>
                    <div className="mt-1 p-2 bg-gray-50 rounded-md">
                      <span className="text-gray-900">
                        {new Date(user.UpdatedAt).toLocaleDateString('en-GB', {
                          year: 'numeric',
                          month: 'long',
                          day: 'numeric',
                        })}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Security Settings */}
            <div className="bg-white shadow rounded-lg">
              <div className="px-6 py-4 border-b border-gray-200">
                <h2 className="text-lg font-semibold text-gray-800">Security Settings</h2>
              </div>
              <div className="px-6 py-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-base font-medium text-gray-900">
                      Two-Factor Authentication
                    </h3>
                    <p className="text-sm text-gray-600 mt-1">
                      Add an extra layer of security to your account with TOTP authentication.
                    </p>
                    <div className="mt-2">
                      {totpEnabled === null ? (
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
                          Loading...
                        </span>
                      ) : totpEnabled ? (
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                          ✓ Enabled
                        </span>
                      ) : (
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                          ✗ Disabled
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="flex space-x-3">
                    {totpEnabled ? (
                      <button
                        onClick={() => setShowDisableForm(true)}
                        className="bg-red-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-red-700 focus:ring-2 focus:ring-red-500 focus:ring-offset-2"
                      >
                        Disable 2FA
                      </button>
                    ) : (
                      <Link
                        href="/auth/totp/setup"
                        className="bg-blue-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-blue-700 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
                      >
                        Enable 2FA
                      </Link>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* TOTP Disable Modal */}
          {showDisableForm && (
            <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
              <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
                <div className="mt-3">
                  <h3 className="text-lg font-medium text-gray-900 mb-4">
                    Disable Two-Factor Authentication
                  </h3>

                  <form onSubmit={disableTOTP}>
                    <div className="mb-4">
                      <label className="block text-sm font-medium text-gray-700 mb-2">
                        Current Password
                      </label>
                      <input
                        type="password"
                        value={disableData.password}
                        onChange={(e) => setDisableData('password', e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-red-500 focus:border-red-500"
                        required
                      />
                    </div>

                    <div className="mb-4">
                      <label className="block text-sm font-medium text-gray-700 mb-2">
                        TOTP Code
                      </label>
                      <input
                        type="text"
                        value={disableData.code}
                        onChange={(e) => setDisableData('code', e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-red-500 focus:border-red-500"
                        placeholder="123456"
                        maxLength={6}
                        required
                      />
                    </div>

                    <div className="bg-yellow-50 border border-yellow-200 p-3 rounded-md mb-4">
                      <p className="text-sm text-yellow-700">
                        <strong>Warning:</strong> Disabling 2FA will make your account less secure.
                      </p>
                    </div>

                    <div className="flex space-x-3">
                      <button
                        type="submit"
                        disabled={disableProcessing}
                        className="flex-1 bg-red-600 text-white py-2 px-4 rounded-md hover:bg-red-700 focus:ring-2 focus:ring-red-500 focus:ring-offset-2 disabled:opacity-50"
                      >
                        {disableProcessing ? 'Disabling...' : 'Disable 2FA'}
                      </button>

                      <button
                        type="button"
                        onClick={() => {
                          setShowDisableForm(false);
                          setDisableData({ password: '', code: '' });
                        }}
                        className="flex-1 bg-gray-300 text-gray-700 py-2 px-4 rounded-md hover:bg-gray-400 focus:ring-2 focus:ring-gray-500 focus:ring-offset-2"
                      >
                        Cancel
                      </button>
                    </div>
                  </form>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
}
