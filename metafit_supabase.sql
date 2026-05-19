-- MetaFit • Supabase / PostgreSQL
-- Rode este arquivo inteiro no SQL Editor do Supabase.
-- Depois, no metafit.html, preencha CONFIG.supabaseUrl e CONFIG.supabaseAnonKey.

create extension if not exists pgcrypto;
create schema if not exists private;

create table if not exists public.metafit_units (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  created_at timestamptz not null default now()
);

create table if not exists public.metafit_consultants (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  unit_id uuid not null references public.metafit_units(id) on delete restrict,
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.metafit_unit_goals (
  id uuid primary key default gen_random_uuid(),
  month_ref date not null,
  unit_id uuid not null references public.metafit_units(id) on delete cascade,
  target numeric(12,2) not null default 0,
  matricula numeric(12,2) not null default 0,
  renovacao numeric(12,2) not null default 0,
  recuperacao numeric(12,2) not null default 0,
  extra numeric(12,2) not null default 0,
  created_at timestamptz not null default now(),
  unique (month_ref, unit_id)
);

create table if not exists public.metafit_consultant_goals (
  id uuid primary key default gen_random_uuid(),
  month_ref date not null,
  consultant_id uuid not null references public.metafit_consultants(id) on delete cascade,
  target numeric(12,2) not null default 0,
  commission_rate numeric(6,2) not null default 0,
  created_at timestamptz not null default now(),
  unique (month_ref, consultant_id)
);

create table if not exists public.metafit_leads (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  phone text,
  source text,
  created_on date not null default current_date,
  unit_id uuid not null references public.metafit_units(id) on delete restrict,
  consultant_id uuid not null references public.metafit_consultants(id) on delete restrict,
  expected_value numeric(12,2) not null default 0,
  status text not null default 'novo' check (status in ('novo','contato','agendado','matriculado','perdido')),
  converted_on date,
  sale_id uuid,
  created_at timestamptz not null default now()
);

create table if not exists public.metafit_sales (
  id uuid primary key default gen_random_uuid(),
  sale_date date not null default current_date,
  unit_id uuid not null references public.metafit_units(id) on delete restrict,
  consultant_id uuid not null references public.metafit_consultants(id) on delete restrict,
  sale_type text not null check (sale_type in ('matricula','renovacao','recuperacao','extra')),
  amount numeric(12,2) not null default 0,
  student text not null,
  lead_id uuid references public.metafit_leads(id) on delete set null,
  extra_detail text,
  notes text,
  created_at timestamptz not null default now()
);

alter table public.metafit_leads
  drop constraint if exists metafit_leads_sale_id_fkey;

alter table public.metafit_leads
  add constraint metafit_leads_sale_id_fkey
  foreign key (sale_id) references public.metafit_sales(id) on delete set null;

create table if not exists public.metafit_users (
  id uuid primary key default gen_random_uuid(),
  login text not null unique,
  password_hash text not null,
  display_name text not null,
  role text not null default 'operador' check (role in ('admin','operador')),
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.metafit_user_units (
  user_id uuid not null references public.metafit_users(id) on delete cascade,
  unit_id uuid not null references public.metafit_units(id) on delete cascade,
  primary key (user_id, unit_id)
);

create table if not exists public.metafit_sessions (
  token_hash text primary key,
  user_id uuid not null references public.metafit_users(id) on delete cascade,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

create index if not exists metafit_consultants_unit_idx on public.metafit_consultants(unit_id);
create index if not exists metafit_unit_goals_month_idx on public.metafit_unit_goals(month_ref, unit_id);
create index if not exists metafit_consultant_goals_month_idx on public.metafit_consultant_goals(month_ref, consultant_id);
create index if not exists metafit_leads_scope_idx on public.metafit_leads(created_on, unit_id, consultant_id);
create index if not exists metafit_sales_scope_idx on public.metafit_sales(sale_date, unit_id, consultant_id);
create index if not exists metafit_sessions_user_idx on public.metafit_sessions(user_id, expires_at);

alter table public.metafit_units enable row level security;
alter table public.metafit_consultants enable row level security;
alter table public.metafit_unit_goals enable row level security;
alter table public.metafit_consultant_goals enable row level security;
alter table public.metafit_leads enable row level security;
alter table public.metafit_sales enable row level security;
alter table public.metafit_users enable row level security;
alter table public.metafit_user_units enable row level security;
alter table public.metafit_sessions enable row level security;

revoke all on table
  public.metafit_units,
  public.metafit_consultants,
  public.metafit_unit_goals,
  public.metafit_consultant_goals,
  public.metafit_leads,
  public.metafit_sales,
  public.metafit_users,
  public.metafit_user_units,
  public.metafit_sessions
from anon, authenticated;

create or replace function private.metafit_context(p_token text)
returns table (
  user_id uuid,
  role text,
  active boolean,
  allowed_unit_ids uuid[]
)
language sql
security definer
set search_path = public, private
as $$
  select
    u.id,
    u.role,
    u.active,
    case
      when u.role = 'admin' then array(select id from public.metafit_units order by name)
      else coalesce(array(select unit_id from public.metafit_user_units where user_id = u.id order by unit_id), '{}'::uuid[])
    end
  from public.metafit_sessions s
  join public.metafit_users u on u.id = s.user_id
  where s.token_hash = encode(digest(coalesce(p_token, ''), 'sha256'), 'hex')
    and s.expires_at > now()
  limit 1;
$$;

create or replace function private.metafit_require_context(p_token text)
returns table (
  user_id uuid,
  role text,
  allowed_unit_ids uuid[]
)
language plpgsql
security definer
set search_path = public, private
as $$
declare
  v_user_id uuid;
  v_role text;
  v_active boolean;
  v_units uuid[];
begin
  select c.user_id, c.role, c.active, c.allowed_unit_ids
    into v_user_id, v_role, v_active, v_units
  from private.metafit_context(p_token) c;

  if v_user_id is null or not coalesce(v_active, false) then
    raise exception 'Sessão inválida ou expirada.';
  end if;

  return query select v_user_id, v_role, coalesce(v_units, '{}'::uuid[]);
end;
$$;

create or replace function private.metafit_require_admin(p_token text)
returns uuid
language plpgsql
security definer
set search_path = public, private
as $$
declare
  v_user_id uuid;
  v_role text;
  v_units uuid[];
begin
  select user_id, role, allowed_unit_ids
    into v_user_id, v_role, v_units
  from private.metafit_require_context(p_token);

  if v_role <> 'admin' then
    raise exception 'Somente ADM pode executar esta ação.';
  end if;

  return v_user_id;
end;
$$;

create or replace function private.metafit_assert_unit_access(p_token text, p_unit_id uuid)
returns void
language plpgsql
security definer
set search_path = public, private
as $$
declare
  v_user_id uuid;
  v_role text;
  v_units uuid[];
begin
  select user_id, role, allowed_unit_ids
    into v_user_id, v_role, v_units
  from private.metafit_require_context(p_token);

  if v_role <> 'admin' and not (p_unit_id = any(v_units)) then
    raise exception 'Este login não pode acessar a unidade informada.';
  end if;
end;
$$;

create or replace function public.metafit_has_admin()
returns boolean
language sql
security definer
set search_path = public, private
as $$
  select exists (
    select 1
    from public.metafit_users
    where role = 'admin'
  );
$$;

create or replace function public.metafit_bootstrap_admin(
  p_login text,
  p_password text,
  p_name text
)
returns table (
  token text,
  id uuid,
  login text,
  nome text,
  perfil text,
  allowed_unit_ids uuid[],
  allowed_unit_names text[]
)
language plpgsql
security definer
set search_path = public, private
as $$
declare
  v_user_id uuid;
  v_token text;
begin
  if exists (select 1 from public.metafit_users where role = 'admin') then
    raise exception 'O primeiro ADM já foi criado.';
  end if;

  if coalesce(length(trim(p_login)), 0) = 0 or coalesce(length(trim(p_password)), 0) < 6 or coalesce(length(trim(p_name)), 0) = 0 then
    raise exception 'Informe login, nome e senha com pelo menos 6 caracteres.';
  end if;

  insert into public.metafit_users (login, password_hash, display_name, role, active)
  values (lower(trim(p_login)), crypt(p_password, gen_salt('bf')), trim(p_name), 'admin', true)
  returning metafit_users.id into v_user_id;

  v_token := encode(gen_random_bytes(32), 'hex');

  insert into public.metafit_sessions (token_hash, user_id, expires_at)
  values (encode(digest(v_token, 'sha256'), 'hex'), v_user_id, now() + interval '30 days');

  return query
  select
    v_token,
    u.id,
    u.login,
    u.display_name,
    u.role,
    array(select id from public.metafit_units order by name),
    array(select name from public.metafit_units order by name)
  from public.metafit_users u
  where u.id = v_user_id;
end;
$$;

create or replace function public.metafit_login(
  p_login text,
  p_password text
)
returns table (
  token text,
  id uuid,
  login text,
  nome text,
  perfil text,
  allowed_unit_ids uuid[],
  allowed_unit_names text[]
)
language plpgsql
security definer
set search_path = public, private
as $$
declare
  v_user public.metafit_users%rowtype;
  v_token text;
begin
  select *
    into v_user
  from public.metafit_users
  where login = lower(trim(p_login))
    and active = true
  limit 1;

  if v_user.id is null or v_user.password_hash <> crypt(coalesce(p_password, ''), v_user.password_hash) then
    raise exception 'Login ou senha inválidos.';
  end if;

  delete from public.metafit_sessions where expires_at <= now();

  v_token := encode(gen_random_bytes(32), 'hex');

  insert into public.metafit_sessions (token_hash, user_id, expires_at)
  values (encode(digest(v_token, 'sha256'), 'hex'), v_user.id, now() + interval '30 days');

  return query
  select
    v_token,
    v_user.id,
    v_user.login,
    v_user.display_name,
    v_user.role,
    case
      when v_user.role = 'admin' then array(select id from public.metafit_units order by name)
      else coalesce(array(select unit_id from public.metafit_user_units where user_id = v_user.id order by unit_id), '{}'::uuid[])
    end,
    case
      when v_user.role = 'admin' then array(select name from public.metafit_units order by name)
      else coalesce(array(
        select u.name
        from public.metafit_user_units uu
        join public.metafit_units u on u.id = uu.unit_id
        where uu.user_id = v_user.id
        order by u.name
      ), '{}'::text[])
    end;
end;
$$;

create or replace function public.metafit_session(p_token text)
returns table (
  id uuid,
  login text,
  nome text,
  perfil text,
  allowed_unit_ids uuid[],
  allowed_unit_names text[]
)
language plpgsql
security definer
set search_path = public, private
as $$
declare
  v_user_id uuid;
  v_role text;
  v_units uuid[];
begin
  select user_id, role, allowed_unit_ids
    into v_user_id, v_role, v_units
  from private.metafit_require_context(p_token);

  return query
  select
    u.id,
    u.login,
    u.display_name,
    u.role,
    coalesce(v_units, '{}'::uuid[]),
    coalesce(array(
      select units.name
      from public.metafit_units units
      where units.id = any(coalesce(v_units, '{}'::uuid[]))
      order by units.name
    ), '{}'::text[])
  from public.metafit_users u
  where u.id = v_user_id;
end;
$$;

create or replace function public.metafit_snapshot(p_token text)
returns jsonb
language plpgsql
security definer
set search_path = public, private
as $$
declare
  v_user_id uuid;
  v_role text;
  v_units uuid[];
  v_payload jsonb;
begin
  select user_id, role, allowed_unit_ids
    into v_user_id, v_role, v_units
  from private.metafit_require_context(p_token);

  select jsonb_build_object(
    'units', coalesce((
      select jsonb_agg(to_jsonb(x) order by x.name)
      from (
        select id, name
        from public.metafit_units
        where v_role = 'admin' or id = any(v_units)
      ) x
    ), '[]'::jsonb),
    'consultants', coalesce((
      select jsonb_agg(to_jsonb(x) order by x.name)
      from (
        select id, name, unit_id as "unitId", active
        from public.metafit_consultants
        where v_role = 'admin' or unit_id = any(v_units)
      ) x
    ), '[]'::jsonb),
    'unitGoals', coalesce((
      select jsonb_agg(to_jsonb(x) order by x.month desc, x."unitId")
      from (
        select
          id,
          to_char(month_ref, 'YYYY-MM') as month,
          unit_id as "unitId",
          target,
          matricula,
          renovacao,
          recuperacao,
          extra
        from public.metafit_unit_goals
        where v_role = 'admin' or unit_id = any(v_units)
      ) x
    ), '[]'::jsonb),
    'consultantGoals', coalesce((
      select jsonb_agg(to_jsonb(x) order by x.month desc, x."consultantId")
      from (
        select
          g.id,
          to_char(g.month_ref, 'YYYY-MM') as month,
          g.consultant_id as "consultantId",
          g.target,
          g.commission_rate as "commissionRate"
        from public.metafit_consultant_goals g
        join public.metafit_consultants c on c.id = g.consultant_id
        where v_role = 'admin' or c.unit_id = any(v_units)
      ) x
    ), '[]'::jsonb),
    'leads', coalesce((
      select jsonb_agg(to_jsonb(x) order by x."createdAt" desc)
      from (
        select
          id,
          name,
          coalesce(phone, '') as phone,
          coalesce(source, '') as source,
          to_char(created_on, 'YYYY-MM-DD') as "createdAt",
          unit_id as "unitId",
          consultant_id as "consultantId",
          expected_value as "expectedValue",
          status,
          coalesce(to_char(converted_on, 'YYYY-MM-DD'), '') as "convertedAt",
          coalesce(sale_id::text, '') as "saleId"
        from public.metafit_leads
        where v_role = 'admin' or unit_id = any(v_units)
      ) x
    ), '[]'::jsonb),
    'sales', coalesce((
      select jsonb_agg(to_jsonb(x) order by x.date desc)
      from (
        select
          id,
          to_char(sale_date, 'YYYY-MM-DD') as date,
          unit_id as "unitId",
          consultant_id as "consultantId",
          sale_type as type,
          amount,
          student,
          coalesce(lead_id::text, '') as "leadId",
          coalesce(extra_detail, '') as "extraDetail",
          coalesce(notes, '') as notes
        from public.metafit_sales
        where v_role = 'admin' or unit_id = any(v_units)
      ) x
    ), '[]'::jsonb)
  )
  into v_payload;

  return v_payload;
end;
$$;

create or replace function public.metafit_save_unit(
  p_token text,
  p_id uuid,
  p_name text
)
returns uuid
language plpgsql
security definer
set search_path = public, private
as $$
declare
  v_id uuid;
begin
  perform private.metafit_require_admin(p_token);

  if coalesce(length(trim(p_name)), 0) = 0 then
    raise exception 'Informe o nome da unidade.';
  end if;

  if p_id is null then
    insert into public.metafit_units (name)
    values (trim(p_name))
    returning id into v_id;
  else
    update public.metafit_units
      set name = trim(p_name)
    where id = p_id
    returning id into v_id;
  end if;

  return v_id;
end;
$$;

create or replace function public.metafit_delete_unit(
  p_token text,
  p_id uuid
)
returns void
language plpgsql
security definer
set search_path = public, private
as $$
begin
  perform private.metafit_require_admin(p_token);
  delete from public.metafit_units where id = p_id;
end;
$$;

create or replace function public.metafit_save_consultant(
  p_token text,
  p_id uuid,
  p_name text,
  p_unit_id uuid,
  p_active boolean
)
returns uuid
language plpgsql
security definer
set search_path = public, private
as $$
declare
  v_id uuid;
begin
  perform private.metafit_require_admin(p_token);

  if coalesce(length(trim(p_name)), 0) = 0 then
    raise exception 'Informe o nome do consultor.';
  end if;

  if p_id is null then
    insert into public.metafit_consultants (name, unit_id, active)
    values (trim(p_name), p_unit_id, coalesce(p_active, true))
    returning id into v_id;
  else
    update public.metafit_consultants
      set name = trim(p_name),
          unit_id = p_unit_id,
          active = coalesce(p_active, true)
    where id = p_id
    returning id into v_id;
  end if;

  return v_id;
end;
$$;

create or replace function public.metafit_delete_consultant(
  p_token text,
  p_id uuid
)
returns void
language plpgsql
security definer
set search_path = public, private
as $$
begin
  perform private.metafit_require_admin(p_token);
  delete from public.metafit_consultants where id = p_id;
end;
$$;

create or replace function public.metafit_save_unit_goal(
  p_token text,
  p_id uuid,
  p_month text,
  p_unit_id uuid,
  p_target numeric,
  p_matricula numeric,
  p_renovacao numeric,
  p_recuperacao numeric,
  p_extra numeric
)
returns uuid
language plpgsql
security definer
set search_path = public, private
as $$
declare
  v_id uuid;
  v_month date := to_date(p_month || '-01', 'YYYY-MM-DD');
begin
  perform private.metafit_require_admin(p_token);

  if p_id is null then
    insert into public.metafit_unit_goals (month_ref, unit_id, target, matricula, renovacao, recuperacao, extra)
    values (v_month, p_unit_id, p_target, p_matricula, p_renovacao, p_recuperacao, p_extra)
    returning id into v_id;
  else
    update public.metafit_unit_goals
      set month_ref = v_month,
          unit_id = p_unit_id,
          target = p_target,
          matricula = p_matricula,
          renovacao = p_renovacao,
          recuperacao = p_recuperacao,
          extra = p_extra
    where id = p_id
    returning id into v_id;
  end if;

  return v_id;
end;
$$;

create or replace function public.metafit_delete_unit_goal(
  p_token text,
  p_id uuid
)
returns void
language plpgsql
security definer
set search_path = public, private
as $$
begin
  perform private.metafit_require_admin(p_token);
  delete from public.metafit_unit_goals where id = p_id;
end;
$$;

create or replace function public.metafit_save_consultant_goal(
  p_token text,
  p_id uuid,
  p_month text,
  p_consultant_id uuid,
  p_target numeric,
  p_commission_rate numeric
)
returns uuid
language plpgsql
security definer
set search_path = public, private
as $$
declare
  v_id uuid;
  v_month date := to_date(p_month || '-01', 'YYYY-MM-DD');
begin
  perform private.metafit_require_admin(p_token);

  if p_id is null then
    insert into public.metafit_consultant_goals (month_ref, consultant_id, target, commission_rate)
    values (v_month, p_consultant_id, p_target, p_commission_rate)
    returning id into v_id;
  else
    update public.metafit_consultant_goals
      set month_ref = v_month,
          consultant_id = p_consultant_id,
          target = p_target,
          commission_rate = p_commission_rate
    where id = p_id
    returning id into v_id;
  end if;

  return v_id;
end;
$$;

create or replace function public.metafit_delete_consultant_goal(
  p_token text,
  p_id uuid
)
returns void
language plpgsql
security definer
set search_path = public, private
as $$
begin
  perform private.metafit_require_admin(p_token);
  delete from public.metafit_consultant_goals where id = p_id;
end;
$$;

create or replace function public.metafit_save_sale(
  p_token text,
  p_id uuid,
  p_date date,
  p_unit_id uuid,
  p_consultant_id uuid,
  p_type text,
  p_amount numeric,
  p_student text,
  p_lead_id uuid,
  p_extra_detail text,
  p_notes text
)
returns uuid
language plpgsql
security definer
set search_path = public, private
as $$
declare
  v_id uuid;
  v_old_lead_id uuid;
begin
  perform private.metafit_assert_unit_access(p_token, p_unit_id);

  if p_amount <= 0 then
    raise exception 'O valor da venda precisa ser maior que zero.';
  end if;

  if p_id is not null then
    select lead_id into v_old_lead_id from public.metafit_sales where id = p_id;
  end if;

  if p_id is null then
    insert into public.metafit_sales (sale_date, unit_id, consultant_id, sale_type, amount, student, lead_id, extra_detail, notes)
    values (p_date, p_unit_id, p_consultant_id, p_type, p_amount, trim(p_student), p_lead_id, p_extra_detail, p_notes)
    returning id into v_id;
  else
    update public.metafit_sales
      set sale_date = p_date,
          unit_id = p_unit_id,
          consultant_id = p_consultant_id,
          sale_type = p_type,
          amount = p_amount,
          student = trim(p_student),
          lead_id = p_lead_id,
          extra_detail = p_extra_detail,
          notes = p_notes
    where id = p_id
    returning id into v_id;
  end if;

  if v_old_lead_id is not null and v_old_lead_id is distinct from p_lead_id then
    update public.metafit_leads
      set sale_id = null,
          converted_on = null,
          status = case when status = 'matriculado' then 'contato' else status end
    where id = v_old_lead_id
      and sale_id = v_id;
  end if;

  if p_lead_id is not null then
    update public.metafit_leads
      set sale_id = v_id,
          converted_on = p_date,
          status = 'matriculado'
    where id = p_lead_id;
  end if;

  return v_id;
end;
$$;

create or replace function public.metafit_delete_sale(
  p_token text,
  p_id uuid
)
returns void
language plpgsql
security definer
set search_path = public, private
as $$
declare
  v_unit_id uuid;
  v_lead_id uuid;
begin
  select unit_id, lead_id
    into v_unit_id, v_lead_id
  from public.metafit_sales
  where id = p_id;

  perform private.metafit_assert_unit_access(p_token, v_unit_id);

  delete from public.metafit_sales where id = p_id;

  if v_lead_id is not null then
    update public.metafit_leads
      set sale_id = null,
          converted_on = null,
          status = case when status = 'matriculado' then 'contato' else status end
    where id = v_lead_id;
  end if;
end;
$$;

create or replace function public.metafit_save_lead(
  p_token text,
  p_id uuid,
  p_name text,
  p_phone text,
  p_source text,
  p_created_on date,
  p_unit_id uuid,
  p_consultant_id uuid,
  p_expected_value numeric,
  p_status text
)
returns uuid
language plpgsql
security definer
set search_path = public, private
as $$
declare
  v_id uuid;
  v_sale_id uuid;
begin
  perform private.metafit_assert_unit_access(p_token, p_unit_id);

  if p_status = 'matriculado' and coalesce(p_expected_value, 0) <= 0 then
    raise exception 'Informe um valor previsto maior que zero para matricular pelo CRM.';
  end if;

  if p_id is null then
    insert into public.metafit_leads (name, phone, source, created_on, unit_id, consultant_id, expected_value, status)
    values (trim(p_name), p_phone, p_source, p_created_on, p_unit_id, p_consultant_id, coalesce(p_expected_value, 0), p_status)
    returning id into v_id;
  else
    update public.metafit_leads
      set name = trim(p_name),
          phone = p_phone,
          source = p_source,
          created_on = p_created_on,
          unit_id = p_unit_id,
          consultant_id = p_consultant_id,
          expected_value = coalesce(p_expected_value, 0),
          status = p_status
    where id = p_id
    returning id, sale_id into v_id, v_sale_id;
  end if;

  select sale_id into v_sale_id from public.metafit_leads where id = v_id;

  if p_status = 'matriculado' and v_sale_id is null then
    insert into public.metafit_sales (sale_date, unit_id, consultant_id, sale_type, amount, student, lead_id, notes)
    values (current_date, p_unit_id, p_consultant_id, 'matricula', p_expected_value, trim(p_name), v_id, 'Venda criada automaticamente pelo CRM')
    returning id into v_sale_id;

    update public.metafit_leads
      set sale_id = v_sale_id,
          converted_on = current_date
    where id = v_id;
  end if;

  return v_id;
end;
$$;

create or replace function public.metafit_change_lead_status(
  p_token text,
  p_id uuid,
  p_status text
)
returns void
language plpgsql
security definer
set search_path = public, private
as $$
declare
  v_lead public.metafit_leads%rowtype;
  v_sale_id uuid;
begin
  select * into v_lead from public.metafit_leads where id = p_id;
  perform private.metafit_assert_unit_access(p_token, v_lead.unit_id);

  if p_status = 'matriculado' and coalesce(v_lead.expected_value, 0) <= 0 then
    raise exception 'Informe um valor previsto maior que zero antes de converter o lead.';
  end if;

  update public.metafit_leads
    set status = p_status
  where id = p_id;

  if p_status = 'matriculado' and v_lead.sale_id is null then
    insert into public.metafit_sales (sale_date, unit_id, consultant_id, sale_type, amount, student, lead_id, notes)
    values (current_date, v_lead.unit_id, v_lead.consultant_id, 'matricula', v_lead.expected_value, v_lead.name, v_lead.id, 'Venda criada automaticamente pelo CRM')
    returning id into v_sale_id;

    update public.metafit_leads
      set sale_id = v_sale_id,
          converted_on = current_date
    where id = p_id;
  end if;
end;
$$;

create or replace function public.metafit_delete_lead(
  p_token text,
  p_id uuid
)
returns void
language plpgsql
security definer
set search_path = public, private
as $$
declare
  v_lead public.metafit_leads%rowtype;
begin
  select * into v_lead from public.metafit_leads where id = p_id;
  perform private.metafit_assert_unit_access(p_token, v_lead.unit_id);

  if v_lead.sale_id is not null then
    raise exception 'Esse lead já virou venda. Exclua a venda vinculada primeiro.';
  end if;

  delete from public.metafit_leads where id = p_id;
end;
$$;

create or replace function public.metafit_list_users(p_token text)
returns table (
  id uuid,
  login text,
  nome text,
  perfil text,
  ativo boolean,
  unit_ids uuid[],
  unit_names text[]
)
language plpgsql
security definer
set search_path = public, private
as $$
begin
  perform private.metafit_require_admin(p_token);

  return query
  select
    u.id,
    u.login,
    u.display_name,
    u.role,
    u.active,
    coalesce(array(
      select uu.unit_id
      from public.metafit_user_units uu
      where uu.user_id = u.id
      order by uu.unit_id
    ), '{}'::uuid[]),
    coalesce(array(
      select units.name
      from public.metafit_user_units uu
      join public.metafit_units units on units.id = uu.unit_id
      where uu.user_id = u.id
      order by units.name
    ), '{}'::text[])
  from public.metafit_users u
  order by case when u.role = 'admin' then 0 else 1 end, u.display_name;
end;
$$;

create or replace function public.metafit_save_user(
  p_token text,
  p_id uuid,
  p_login text,
  p_password text,
  p_name text,
  p_role text,
  p_unit_ids uuid[],
  p_active boolean
)
returns uuid
language plpgsql
security definer
set search_path = public, private
as $$
declare
  v_id uuid;
begin
  perform private.metafit_require_admin(p_token);

  if coalesce(length(trim(p_login)), 0) = 0 or coalesce(length(trim(p_name)), 0) = 0 then
    raise exception 'Informe login e nome.';
  end if;

  if p_role not in ('admin','operador') then
    raise exception 'Perfil inválido.';
  end if;

  if p_role <> 'admin' and coalesce(array_length(p_unit_ids, 1), 0) = 0 then
    raise exception 'Selecione ao menos uma unidade para o usuário.';
  end if;

  if p_id is null then
    if coalesce(length(trim(p_password)), 0) < 6 then
      raise exception 'A senha inicial precisa ter ao menos 6 caracteres.';
    end if;

    insert into public.metafit_users (login, password_hash, display_name, role, active)
    values (lower(trim(p_login)), crypt(p_password, gen_salt('bf')), trim(p_name), p_role, coalesce(p_active, true))
    returning id into v_id;
  else
    update public.metafit_users
      set login = lower(trim(p_login)),
          display_name = trim(p_name),
          role = p_role,
          active = coalesce(p_active, true),
          password_hash = case
            when coalesce(length(trim(p_password)), 0) >= 6 then crypt(p_password, gen_salt('bf'))
            else password_hash
          end
    where id = p_id
    returning id into v_id;
  end if;

  delete from public.metafit_user_units where user_id = v_id;

  if p_role <> 'admin' then
    insert into public.metafit_user_units (user_id, unit_id)
    select v_id, unit_id
    from unnest(coalesce(p_unit_ids, '{}'::uuid[])) as unit_id;
  end if;

  return v_id;
end;
$$;

create or replace function public.metafit_delete_user(
  p_token text,
  p_id uuid
)
returns void
language plpgsql
security definer
set search_path = public, private
as $$
declare
  v_role text;
begin
  perform private.metafit_require_admin(p_token);

  select role into v_role from public.metafit_users where id = p_id;

  if v_role = 'admin' and (
    select count(*)
    from public.metafit_users
    where role = 'admin'
  ) <= 1 then
    raise exception 'Não é possível excluir o último ADM.';
  end if;

  delete from public.metafit_users where id = p_id;
end;
$$;

grant usage on schema public to anon, authenticated;

grant execute on function public.metafit_has_admin() to anon, authenticated;
grant execute on function public.metafit_bootstrap_admin(text, text, text) to anon, authenticated;
grant execute on function public.metafit_login(text, text) to anon, authenticated;
grant execute on function public.metafit_session(text) to anon, authenticated;
grant execute on function public.metafit_snapshot(text) to anon, authenticated;
grant execute on function public.metafit_save_unit(text, uuid, text) to anon, authenticated;
grant execute on function public.metafit_delete_unit(text, uuid) to anon, authenticated;
grant execute on function public.metafit_save_consultant(text, uuid, text, uuid, boolean) to anon, authenticated;
grant execute on function public.metafit_delete_consultant(text, uuid) to anon, authenticated;
grant execute on function public.metafit_save_unit_goal(text, uuid, text, uuid, numeric, numeric, numeric, numeric, numeric) to anon, authenticated;
grant execute on function public.metafit_delete_unit_goal(text, uuid) to anon, authenticated;
grant execute on function public.metafit_save_consultant_goal(text, uuid, text, uuid, numeric, numeric) to anon, authenticated;
grant execute on function public.metafit_delete_consultant_goal(text, uuid) to anon, authenticated;
grant execute on function public.metafit_save_sale(text, uuid, date, uuid, uuid, text, numeric, text, uuid, text, text) to anon, authenticated;
grant execute on function public.metafit_delete_sale(text, uuid) to anon, authenticated;
grant execute on function public.metafit_save_lead(text, uuid, text, text, text, date, uuid, uuid, numeric, text) to anon, authenticated;
grant execute on function public.metafit_change_lead_status(text, uuid, text) to anon, authenticated;
grant execute on function public.metafit_delete_lead(text, uuid) to anon, authenticated;
grant execute on function public.metafit_list_users(text) to anon, authenticated;
grant execute on function public.metafit_save_user(text, uuid, text, text, text, text, uuid[], boolean) to anon, authenticated;
grant execute on function public.metafit_delete_user(text, uuid) to anon, authenticated;

insert into public.metafit_units (name)
values
  ('UR-3'),
  ('UR-2'),
  ('Jaboatão'),
  ('Ibura de Baixo')
on conflict (name) do nothing;
