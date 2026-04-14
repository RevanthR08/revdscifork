'use client';

import React from 'react';
import { motion } from 'framer-motion';
import { Button } from '@/components/ui/button';

import {
	AtSignIcon,
	ChevronLeftIcon,
} from 'lucide-react';
import { Input } from '@/components/ui/input';
import { cn } from '@/lib/utils';

import { useRouter } from 'next/router';

export function AuthPage() {
	const router = useRouter();
	const [email, setEmail] = React.useState('');
	const [password, setPassword] = React.useState('');
	const [loading, setLoading] = React.useState(false);

	// Check if already logged in on mount
	React.useEffect(() => {
		const session = localStorage.getItem('auth_session');
		if (session) {
			router.push('/dashboard');
		}
	}, [router]);

	const handleLogin = async (e: React.FormEvent) => {
		e.preventDefault();
		if (!email || !password) return;
		
		setLoading(true);
		// Simulate API call
		await new Promise((res) => setTimeout(res, 800));
		
		localStorage.setItem('auth_session', JSON.stringify({
			email,
			name: email.split('@')[0],
			lastLogin: new Date().toISOString()
		}));
		
		setLoading(false);
		router.push('/dashboard');
	};

	return (
		<main className="relative md:h-screen md:overflow-hidden lg:grid lg:grid-cols-2">
			<div className="bg-muted/60 relative hidden h-full flex-col border-r p-10 lg:flex">
				<div className="from-background absolute inset-0 z-10 bg-gradient-to-t to-transparent" />
				<div className="z-10 flex items-center gap-2">
					<img src="/logo.png" alt="4SIC" className="w-10 h-10" />
					<p className="font-montserrat text-2xl font-extrabold text-foreground tracking-tight leading-none">4SIC <span className="text-blue-500"></span></p>
				</div>
				<div className="z-10 mt-auto text-foreground">
					<blockquote className="space-y-2">
						<p className="text-xl font-medium leading-relaxed">
							&ldquo;Accelerating digital investigations with AI-driven log analysis and automated threat chain mapping.&rdquo;
						</p>
						<footer className="font-mono text-xs font-semibold text-zinc-500 flex items-center gap-2">
							<span className="w-4 h-px bg-zinc-700" /> Lead Forensic Analyst
						</footer>
					</blockquote>
				</div>
				<div className="absolute inset-0">
					<FloatingPaths position={1} />
					<FloatingPaths position={-1} />
				</div>
			</div>
			<div className="relative flex min-h-screen flex-col justify-center p-4 bg-background">
				<div
					aria-hidden
					className="absolute inset-0 isolate contain-strict -z-10 opacity-60"
				>
					<div className="bg-[radial-gradient(68.54%_68.72%_at_55.02%_31.46%,hsl(var(--foreground)/0.06)_0,hsla(0,0%,55%,.02)_50%,hsl(var(--foreground)/0.01)_80%)] absolute top-0 right-0 h-320 w-140 -translate-y-87.5 rounded-full" />
					<div className="bg-[radial-gradient(50%_50%_at_50%_50%,hsl(var(--foreground)/0.04)_0,hsl(var(--foreground)/0.01)_80%,transparent_100%)] absolute top-0 right-0 h-320 w-60 [translate:5%_-50%] rounded-full" />
					<div className="bg-[radial-gradient(50%_50%_at_50%_50%,hsl(var(--foreground)/0.04)_0,hsl(var(--foreground)/0.01)_80%,transparent_100%)] absolute top-0 right-0 h-320 w-60 -translate-y-87.5 rounded-full" />
				</div>
				<Button variant="ghost" className="absolute top-7 left-5" asChild>
					<a href="/">
						<ChevronLeftIcon className='size-4 me-2' />
						Home
					</a>
				</Button>
				<div className="mx-auto space-y-6 w-full max-w-[280px]">
					<div className="flex items-center gap-2 lg:hidden">
						<img src="/logo.png" alt="4SIC" className="w-7 h-7" />
						<p className="font-montserrat text-xl font-extrabold">4SIC</p>
					</div>
					<div className="flex flex-col space-y-1">
						<h1 className="font-heading text-xl font-bold tracking-tight">
							Forensic Portal
						</h1>
						<p className="text-zinc-500 text-xs">
							Enter your credentials to access the SOC dashboard.
						</p>
					</div>

					<form className="space-y-4" onSubmit={handleLogin}>
						<div className="space-y-3">
							<div className="relative h-max">
								<Input
									placeholder="Analyst Email"
									className="peer ps-8 h-9 text-xs"
									type="email"
									required
									value={email}
									onChange={(e) => setEmail(e.target.value)}
								/>
								<div className="text-muted-foreground pointer-events-none absolute inset-y-0 start-0 flex items-center justify-center ps-2.5 peer-disabled:opacity-50">
									<AtSignIcon className="size-3.5" aria-hidden="true" />
								</div>
							</div>
							<div className="relative h-max">
								<Input
									placeholder="Password"
									className="peer ps-8 h-9 text-xs"
									type="password"
									required
									value={password}
									onChange={(e) => setPassword(e.target.value)}
								/>
								<div className="text-muted-foreground pointer-events-none absolute inset-y-0 start-0 flex items-center justify-center ps-2.5 peer-disabled:opacity-50">
									<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="size-3.5"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
								</div>
							</div>
						</div>

						<Button type="submit" className="w-full h-9 text-xs font-semibold" disabled={loading}>
							<span>{loading ? 'Authenticating...' : 'Sign In'}</span>
						</Button>
					</form>
					<p className="text-zinc-600 mt-8 text-[10px] leading-relaxed">
						Access restricted to authorized personnel. All activities are monitored and logged. See our{' '}
						<a
							href="#"
							className="hover:text-blue-400 underline underline-offset-2"
						>
							Security Policy
						</a>.
					</p>
				</div>
			</div>
		</main>
	);
}

function FloatingPaths({ position }: { position: number }) {
	const paths = Array.from({ length: 36 }, (_, i) => ({
		id: i,
		d: `M-${380 - i * 5 * position} -${189 + i * 6}C-${
			380 - i * 5 * position
		} -${189 + i * 6} -${312 - i * 5 * position} ${216 - i * 6} ${
			152 - i * 5 * position
		} ${343 - i * 6}C${616 - i * 5 * position} ${470 - i * 6} ${
			684 - i * 5 * position
		} ${875 - i * 6} ${684 - i * 5 * position} ${875 - i * 6}`,
		color: `rgba(15,23,42,${0.1 + i * 0.03})`,
		width: 0.5 + i * 0.03,
	}));

	return (
		<div className="pointer-events-none absolute inset-0">
			<svg
				className="h-full w-full text-slate-950 dark:text-white"
				viewBox="0 0 696 316"
				fill="none"
			>
				<title>Background Paths</title>
				{paths.map((path) => (
					<motion.path
						key={path.id}
						d={path.d}
						stroke="currentColor"
						strokeWidth={path.width}
						strokeOpacity={0.1 + path.id * 0.03}
						initial={{ pathLength: 0.3, opacity: 0.6 }}
						animate={{
							pathLength: 1,
							opacity: [0.3, 0.6, 0.3],
							pathOffset: [0, 1, 0],
						}}
						transition={{
							duration: 20 + Math.random() * 10,
							repeat: Number.POSITIVE_INFINITY,
							ease: 'linear',
						}}
					/>
				))}
			</svg>
		</div>
	);
}

const GoogleIcon = (props: React.ComponentProps<'svg'>) => (
	<svg
		xmlns="http://www.w3.org/2000/svg"
		viewBox="0 0 24 24"
		fill="currentColor"
		{...props}
	>
		<g>
			<path d="M12.479,14.265v-3.279h11.049c0.108,0.571,0.164,1.247,0.164,1.979c0,2.46-0.672,5.502-2.84,7.669   C18.744,22.829,16.051,24,12.483,24C5.869,24,0.308,18.613,0.308,12S5.869,0,12.483,0c3.659,0,6.265,1.436,8.223,3.307L18.392,5.62   c-1.404-1.317-3.307-2.341-5.913-2.341C7.65,3.279,3.873,7.171,3.873,12s3.777,8.721,8.606,8.721c3.132,0,4.916-1.258,6.059-2.401   c0.927-0.927,1.537-2.251,1.777-4.059L12.479,14.265z" />
		</g>
	</svg>
);

const AuthSeparator = () => {
	return (
		<div className="flex w-full items-center justify-center">
			<div className="bg-border h-px w-full" />
			<span className="text-muted-foreground px-2 text-xs">OR</span>
			<div className="bg-border h-px w-full" />
		</div>
	);
};
