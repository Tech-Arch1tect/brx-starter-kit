import { Head, Link, useForm } from '@inertiajs/react';
import Layout from '../../components/Layout';
import { FlashMessage } from '../../types';

interface Props {
  title: string;
  qrCodeURI: string;
  secret: string;
  flash?: FlashMessage;
  csrfToken?: string;
}

interface FormData {
  code: string;
}

export default function TOTPSetup({ title, qrCodeURI, secret, flash, csrfToken }: Props) {
  const { data, setData, post, processing, errors } = useForm<FormData>({
    code: '',
  });

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    post('/auth/totp/enable', {
      headers: {
        'X-CSRF-Token': csrfToken || '',
      },
    });
  };

  return (
    <Layout>
      <Head title={title} />

      <div className="max-w-2xl mx-auto p-6">
        <div className="bg-white shadow-lg rounded-lg p-8">
          <h1 className="text-2xl font-bold text-gray-900 mb-6">Setup Two-Factor Authentication</h1>

          {flash && (
            <div
              className={`mb-6 px-4 py-3 rounded ${
                flash.type === 'success'
                  ? 'text-green-700 bg-green-50 border border-green-200'
                  : flash.type === 'error'
                    ? 'text-red-700 bg-red-50 border border-red-200'
                    : flash.type === 'warning'
                      ? 'text-yellow-700 bg-yellow-50 border border-yellow-200'
                      : 'text-blue-700 bg-blue-50 border border-blue-200'
              }`}
            >
              {flash.message}
            </div>
          )}

          <div className="space-y-6">
            <div>
              <h2 className="text-lg font-semibold text-gray-800 mb-3">Step 1: Scan QR Code</h2>
              <p className="text-gray-600 mb-4">
                Use your authenticator app (Google Authenticator, Authy, etc.) to scan this QR code:
              </p>

              <div className="bg-gray-50 p-4 rounded-lg text-center">
                <img
                  src={`https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(qrCodeURI)}`}
                  alt="TOTP QR Code"
                  className="mx-auto"
                />
              </div>
            </div>

            <div>
              <h2 className="text-lg font-semibold text-gray-800 mb-3">Step 2: Manual Entry</h2>
              <p className="text-gray-600 mb-2">
                Or enter this secret manually in your authenticator app:
              </p>

              <div className="bg-gray-50 p-3 rounded">
                <code className="text-sm break-all">{secret}</code>
              </div>
            </div>

            <form onSubmit={submit}>
              <h2 className="text-lg font-semibold text-gray-800 mb-3">Step 3: Verify Setup</h2>
              <p className="text-gray-600 mb-4">
                Enter the 6-digit code from your authenticator app:
              </p>

              <div className="mb-4">
                <input
                  type="text"
                  value={data.code}
                  onChange={(e) => setData('code', e.target.value)}
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="123456"
                  maxLength={6}
                  pattern="[0-9]{6}"
                  required
                />
                {errors.code && <div className="mt-2 text-red-600 text-sm">{errors.code}</div>}
              </div>

              <div className="flex gap-4">
                <button
                  type="submit"
                  disabled={processing}
                  className="flex-1 bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-700 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:opacity-50"
                >
                  {processing ? 'Verifying...' : 'Enable Two-Factor Auth'}
                </button>

                <Link
                  href="/profile"
                  className="flex-1 bg-gray-300 text-gray-700 py-2 px-4 rounded-lg hover:bg-gray-400 focus:ring-2 focus:ring-gray-500 focus:ring-offset-2 text-center"
                >
                  Cancel
                </Link>
              </div>
            </form>

            <div className="bg-blue-50 border border-blue-200 p-4 rounded-lg">
              <p className="text-sm text-blue-700">
                <strong>Note:</strong> Keep your authenticator app secure. You'll need it to log in
                once TOTP is enabled.
              </p>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
}
