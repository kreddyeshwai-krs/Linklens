-- Link Lens: 002_rls_policies.sql
-- Row Level Security (RLS) Policies and Role Enforcement

-- Enable RLS on all tables
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.learning_scenarios ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.learning_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.quizzes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.quiz_questions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.quiz_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.admin_audit_logs ENABLE ROW LEVEL SECURITY;

-- Helper function to check if the executing context is an administrator or service_role
CREATE OR REPLACE FUNCTION public.is_admin()
RETURNS BOOLEAN AS $$
DECLARE
    is_admin_user BOOLEAN;
BEGIN
    -- 1. Backend server operations using service_role bypass user checks
    IF (COALESCE(current_setting('request.jwt.claim.role', true), '') = 'service_role') THEN
        RETURN true;
    END IF;

    -- 2. Unauthenticated calls cannot be admin
    IF (auth.uid() IS NULL) THEN
        RETURN false;
    END IF;

    -- 3. Query profiles directly with single-row lookup
    SELECT (role = 'admin') INTO is_admin_user
    FROM public.profiles
    WHERE id = auth.uid();

    RETURN COALESCE(is_admin_user, false);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER STABLE SET search_path = public, pg_temp;

-- Privilege escalation defense: Trigger preventing non-admins from changing roles
CREATE OR REPLACE FUNCTION public.protect_profile_role()
RETURNS TRIGGER AS $$
BEGIN
    IF (NEW.role IS DISTINCT FROM OLD.role) THEN
        IF NOT public.is_admin() THEN
            RAISE EXCEPTION 'Unauthorized: Only administrators can modify user roles';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp;

DROP TRIGGER IF EXISTS tr_protect_profile_role ON public.profiles;
CREATE TRIGGER tr_protect_profile_role
    BEFORE UPDATE ON public.profiles
    FOR EACH ROW
    EXECUTE FUNCTION public.protect_profile_role();

-- =========================================================================
-- 1. PROFILES POLICIES
-- =========================================================================
-- Users can view their own profile; admins can view all profiles
CREATE POLICY "Users can view own profile or admins view all"
    ON public.profiles FOR SELECT
    USING (auth.uid() = id OR public.is_admin());

-- Users can update only their own profile; role changes are gated by tr_protect_profile_role
CREATE POLICY "Users can update own profile or admins update any"
    ON public.profiles FOR UPDATE
    USING (auth.uid() = id OR public.is_admin())
    WITH CHECK (auth.uid() = id OR public.is_admin());

-- =========================================================================
-- 2. SCANS POLICIES
-- =========================================================================
-- Users can view only their own scans; admins can view all
CREATE POLICY "Users can view own scans"
    ON public.scans FOR SELECT
    USING (auth.uid() = user_id OR public.is_admin());

-- Users can insert scans for themselves
CREATE POLICY "Users can insert own scans"
    ON public.scans FOR INSERT
    WITH CHECK (auth.uid() = user_id OR public.is_admin());

-- Users can delete only their own scans
CREATE POLICY "Users can delete own scans"
    ON public.scans FOR DELETE
    USING (auth.uid() = user_id OR public.is_admin());

-- =========================================================================
-- 3. LEARNING SCENARIOS POLICIES
-- =========================================================================
-- Anyone authenticated can view enabled scenarios
CREATE POLICY "Authenticated users view enabled scenarios"
    ON public.learning_scenarios FOR SELECT
    USING (enabled = true OR public.is_admin());

-- Only admins can insert, update, or delete scenarios
CREATE POLICY "Admins manage scenarios insert"
    ON public.learning_scenarios FOR INSERT
    WITH CHECK (public.is_admin());

CREATE POLICY "Admins manage scenarios update"
    ON public.learning_scenarios FOR UPDATE
    USING (public.is_admin())
    WITH CHECK (public.is_admin());

CREATE POLICY "Admins manage scenarios delete"
    ON public.learning_scenarios FOR DELETE
    USING (public.is_admin());

-- Safe Public View for Scenarios (excludes correct_indicators)
CREATE OR REPLACE VIEW public.v_public_learning_scenarios AS
SELECT 
    id,
    title,
    description,
    difficulty,
    category,
    sample_url,
    public_explanation,
    safer_action,
    enabled,
    version,
    created_at,
    updated_at
FROM public.learning_scenarios
WHERE enabled = true;

-- =========================================================================
-- 4. LEARNING ATTEMPTS POLICIES
-- =========================================================================
-- Users can view only their own learning attempts
CREATE POLICY "Users view own learning attempts"
    ON public.learning_attempts FOR SELECT
    USING (auth.uid() = user_id OR public.is_admin());

-- Users can insert their own attempts
CREATE POLICY "Users insert own learning attempts"
    ON public.learning_attempts FOR INSERT
    WITH CHECK (auth.uid() = user_id OR public.is_admin());

-- =========================================================================
-- 5. QUIZZES & QUIZ QUESTIONS POLICIES
-- =========================================================================
-- Users view enabled quizzes
CREATE POLICY "Users view enabled quizzes"
    ON public.quizzes FOR SELECT
    USING (enabled = true OR public.is_admin());

CREATE POLICY "Admins manage quizzes"
    ON public.quizzes FOR ALL
    USING (public.is_admin())
    WITH CHECK (public.is_admin());

-- Safe Public View for Quiz Questions (excludes correct_answer column)
CREATE OR REPLACE VIEW public.v_public_quiz_questions AS
SELECT 
    id,
    quiz_id,
    question_text,
    question_type,
    public_options,
    points,
    order_index,
    enabled
FROM public.quiz_questions
WHERE enabled = true;

-- For direct table select on quiz_questions, only admins can view directly
CREATE POLICY "Admins view all quiz questions directly"
    ON public.quiz_questions FOR SELECT
    USING (public.is_admin());

CREATE POLICY "Admins manage quiz questions"
    ON public.quiz_questions FOR ALL
    USING (public.is_admin())
    WITH CHECK (public.is_admin());

-- =========================================================================
-- 6. QUIZ ATTEMPTS POLICIES
-- =========================================================================
CREATE POLICY "Users view own quiz attempts"
    ON public.quiz_attempts FOR SELECT
    USING (auth.uid() = user_id OR public.is_admin());

CREATE POLICY "Users insert own quiz attempts"
    ON public.quiz_attempts FOR INSERT
    WITH CHECK (auth.uid() = user_id OR public.is_admin());

-- =========================================================================
-- 7. ADMIN AUDIT LOGS POLICIES
-- =========================================================================
CREATE POLICY "Only admins view audit logs"
    ON public.admin_audit_logs FOR SELECT
    USING (public.is_admin());

-- Audits are inserted by backend service or admin
CREATE POLICY "Admins or server insert audit logs"
    ON public.admin_audit_logs FOR INSERT
    WITH CHECK (public.is_admin());

-- =========================================================================
-- 8. PERMISSIONS & PUBLIC VIEW GRANTS
-- =========================================================================
GRANT USAGE ON SCHEMA public TO anon, authenticated;
GRANT SELECT ON public.v_public_learning_scenarios TO anon, authenticated;
GRANT SELECT ON public.v_public_quiz_questions TO anon, authenticated;
GRANT ALL ON ALL TABLES IN SCHEMA public TO authenticated;
GRANT SELECT ON public.learning_scenarios TO anon;
GRANT SELECT ON public.quizzes TO anon;

-- =========================================================================
-- 9. SUPABASE STORAGE (Reports & Assets Bucket)
-- =========================================================================
INSERT INTO storage.buckets (id, name, public)
VALUES ('reports', 'reports', false)
ON CONFLICT (id) DO NOTHING;

-- Storage RLS: Users can view their own reports or admins view all
CREATE POLICY "Users view own reports"
    ON storage.objects FOR SELECT
    USING (bucket_id = 'reports' AND ((storage.foldername(name))[1] = auth.uid()::text OR public.is_admin()));

-- Users or service role can upload reports
CREATE POLICY "Users upload own reports"
    ON storage.objects FOR INSERT
    WITH CHECK (bucket_id = 'reports' AND ((storage.foldername(name))[1] = auth.uid()::text OR public.is_admin()));

-- Users or admins can delete reports
CREATE POLICY "Users delete own reports"
    ON storage.objects FOR DELETE
    USING (bucket_id = 'reports' AND ((storage.foldername(name))[1] = auth.uid()::text OR public.is_admin()));
