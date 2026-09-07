"use client";

import Link from "next/link";
import { useFormState, useFormStatus } from "react-dom";

import { loginAction, registerAction, type FormState } from "@/lib/actions";

function SubmitButton({ label }: { label: string }) {
  const { pending } = useFormStatus();
  return (
    <button type="submit" className="btn-primary w-full" disabled={pending}>
      {pending ? "Please wait…" : label}
    </button>
  );
}

export default function AuthForm({ mode }: { mode: "login" | "register" }) {
  const isRegister = mode === "register";
  const [state, formAction] = useFormState<FormState, FormData>(
    isRegister ? registerAction : loginAction,
    {},
  );

  return (
    <div className="mx-auto w-full max-w-sm space-y-6">
      <div className="text-center">
        <h1 className="text-2xl font-semibold text-slate-100">
          {isRegister ? "Create your account" : "Sign in to Vaultly"}
        </h1>
        <p className="mt-1 text-sm text-slate-400">
          {isRegister
            ? "You will get a personal workspace to start from."
            : "Encrypted secrets for your team."}
        </p>
      </div>

      <form action={formAction} className="card space-y-4 p-6">
        {isRegister && (
          <div>
            <label className="label" htmlFor="name">
              Name
            </label>
            <input id="name" name="name" className="input" autoComplete="name" required />
            {state.fields?.name && <p className="mt-1 text-xs text-red-400">{state.fields.name}</p>}
          </div>
        )}

        <div>
          <label className="label" htmlFor="email">
            Email
          </label>
          <input
            id="email"
            name="email"
            type="email"
            className="input"
            autoComplete="email"
            required
          />
          {state.fields?.email && <p className="mt-1 text-xs text-red-400">{state.fields.email}</p>}
        </div>

        <div>
          <label className="label" htmlFor="password">
            Password
          </label>
          <input
            id="password"
            name="password"
            type="password"
            className="input"
            autoComplete={isRegister ? "new-password" : "current-password"}
            minLength={isRegister ? 12 : undefined}
            required
          />
          {isRegister && (
            <p className="mt-1 text-xs text-slate-500">At least 12 characters.</p>
          )}
          {state.fields?.password && (
            <p className="mt-1 text-xs text-red-400">{state.fields.password}</p>
          )}
        </div>

        {state.error && !state.fields && (
          <p role="alert" className="text-sm text-red-400">
            {state.error}
          </p>
        )}

        <SubmitButton label={isRegister ? "Create account" : "Sign in"} />
      </form>

      <p className="text-center text-sm text-slate-400">
        {isRegister ? (
          <>
            Already have an account?{" "}
            <Link href="/login" className="text-accent-soft hover:underline">
              Sign in
            </Link>
          </>
        ) : (
          <>
            New here?{" "}
            <Link href="/register" className="text-accent-soft hover:underline">
              Create an account
            </Link>
          </>
        )}
      </p>
    </div>
  );
}
