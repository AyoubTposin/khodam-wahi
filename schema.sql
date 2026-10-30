-- نظام خدام الوحي — قاعدة البيانات المشتركة (Supabase)
-- نفّذ الملف كاملاً مرة واحدة في SQL Editor داخل مشروع Supabase جديد.
-- لا تستخدم service_role في المتصفح أبداً.

create table if not exists public.qw_schools (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 2 and 100),
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now()
);

create table if not exists public.qw_members (
  school_id uuid not null references public.qw_schools(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null check (role in ('owner','editor')),
  joined_at timestamptz not null default now(),
  primary key (school_id, user_id)
);
create index if not exists qw_members_user_idx on public.qw_members(user_id);

create table if not exists public.qw_data (
  school_id uuid primary key references public.qw_schools(id) on delete cascade,
  payload jsonb not null,
  revision bigint not null default 0,
  updated_at timestamptz not null default now()
);

create table if not exists public.qw_invites (
  id uuid primary key default gen_random_uuid(),
  school_id uuid not null references public.qw_schools(id) on delete cascade,
  token_hash text not null unique,
  created_by uuid not null references auth.users(id),
  expires_at timestamptz not null,
  uses_left integer not null default 1 check (uses_left between 0 and 10),
  created_at timestamptz not null default now()
);
create index if not exists qw_invites_expire_idx on public.qw_invites(expires_at);

alter table public.qw_schools enable row level security;
alter table public.qw_members enable row level security;
alter table public.qw_data enable row level security;
alter table public.qw_invites enable row level security;

-- مبدئياً لا توجد أي صلاحية لتعديل الجداول مباشرة من المتصفح.
revoke all on table public.qw_schools, public.qw_members, public.qw_data, public.qw_invites from PUBLIC, anon, authenticated;
grant select on table public.qw_schools, public.qw_members, public.qw_data to authenticated;

-- دالة خاصة تكسر تداخل RLS مع جدول الأعضاء.
create or replace function public.qw_is_member(p_school_id uuid)
returns boolean
language sql stable security definer set search_path = ''
as $$
  select exists(
    select 1 from public.qw_members m
    where m.school_id = p_school_id and m.user_id = (select auth.uid())
  );
$$;

create policy "qw_read_school" on public.qw_schools
 for select to authenticated using (public.qw_is_member(id));
create policy "qw_read_members" on public.qw_members
 for select to authenticated using (public.qw_is_member(school_id));
create policy "qw_read_school_data" on public.qw_data
 for select to authenticated using (public.qw_is_member(school_id));
-- لا يوجد أي policy على qw_invites: الدوال المقيّدة هي وحدها تتعامل معها.

create or replace function public.qw_create_school(p_name text)
returns uuid language plpgsql security definer set search_path = ''
as $$
declare v_id uuid; v_uid uuid := (select auth.uid()); v_name text := btrim(p_name);
begin
  if v_uid is null then raise exception 'AUTH_REQUIRED'; end if;
  if v_name is null or char_length(v_name) not between 2 and 100 then
    raise exception 'INVALID_SCHOOL_NAME'; end if;
  insert into public.qw_schools(name,created_by) values(v_name,v_uid) returning id into v_id;
  insert into public.qw_members(school_id,user_id,role) values(v_id,v_uid,'owner');
  insert into public.qw_data(school_id,payload) values(v_id, jsonb_build_object(
    'version',1,
    'settings',jsonb_build_object('schoolName',v_name,'city','الجزائر',
      'year',extract(year from now())::text || '/' || (extract(year from now())::int+1)::text,
      'phone','','director',''),
    'students','[]'::jsonb,'teachers','[]'::jsonb,'circles','[]'::jsonb,
    'attendance','[]'::jsonb,'memorization','[]'::jsonb,
    'transactions','[]'::jsonb,'demo',false));
  return v_id;
end;
$$;

-- تعديل متفائل: إذا كتب مستخدم آخر قبلنا، نطلب دمج التغييرات بدل مسحها.
create or replace function public.qw_save_data(
  p_school_id uuid, p_expected_revision bigint, p_payload jsonb)
returns bigint language plpgsql security definer set search_path = ''
as $$
declare v_revision bigint;
begin
  if (select auth.uid()) is null or not public.qw_is_member(p_school_id) then
    raise exception 'NOT_A_MEMBER'; end if;
  if p_payload is null or jsonb_typeof(p_payload) <> 'object'
     or jsonb_typeof(p_payload->'settings') <> 'object'
     or jsonb_typeof(p_payload->'students') <> 'array'
     or jsonb_typeof(p_payload->'teachers') <> 'array'
     or jsonb_typeof(p_payload->'circles') <> 'array'
     or jsonb_typeof(p_payload->'attendance') <> 'array'
     or jsonb_typeof(p_payload->'memorization') <> 'array'
     or jsonb_typeof(p_payload->'transactions') <> 'array'
     or octet_length(p_payload::text) > 10000000 then
    raise exception 'INVALID_OR_TOO_LARGE_PAYLOAD'; end if;
  update public.qw_data set payload=p_payload, revision=revision+1,updated_at=now()
   where school_id=p_school_id and revision=p_expected_revision
   returning revision into v_revision;
  if not found then raise exception 'VERSION_CONFLICT'; end if;
  return v_revision;
end;
$$;

-- الكود عشوائي قوي، نخزن بصمته فقط، صالح 7 أيام ولاستعمال واحد.
create or replace function public.qw_create_invite(p_school_id uuid)
returns text language plpgsql security definer set search_path = ''
as $$
declare v_uid uuid := (select auth.uid()); v_token text;
begin
  if not exists(select 1 from public.qw_members
       where school_id=p_school_id and user_id=v_uid and role='owner') then
    raise exception 'OWNER_ONLY'; end if;
  v_token := replace(gen_random_uuid()::text,'-','');
  insert into public.qw_invites(school_id,token_hash,created_by,expires_at)
    values(p_school_id,md5(v_token),v_uid,now()+interval '7 days');
  return v_token;
end;
$$;

create or replace function public.qw_join_school(p_code text)
returns uuid language plpgsql security definer set search_path = ''
as $$
declare v_uid uuid := (select auth.uid()); v_id uuid;
        v_code text := lower(btrim(p_code));
begin
  if v_uid is null then raise exception 'AUTH_REQUIRED'; end if;
  if v_code !~ '^[a-f0-9]{32}$' then raise exception 'INVALID_INVITE'; end if;
  update public.qw_invites
     set uses_left=uses_left-1
     where token_hash=md5(v_code) and expires_at>now() and uses_left>0
     returning school_id into v_id;
  if v_id is null then raise exception 'INVITE_EXPIRED_OR_USED'; end if;
  insert into public.qw_members(school_id,user_id,role)
     values(v_id,v_uid,'editor') on conflict (school_id,user_id) do nothing;
  return v_id;
end;
$$;

create or replace function public.qw_list_team(p_school_id uuid)
returns table(user_id uuid, email text, role text, joined_at timestamptz)
language sql stable security definer set search_path = ''
as $$
  select m.user_id, u.email::text, m.role, m.joined_at
   from public.qw_members m join auth.users u on u.id=m.user_id
  where m.school_id=p_school_id and public.qw_is_member(p_school_id)
  order by case when m.role='owner' then 0 else 1 end,m.joined_at;
$$;

create or replace function public.qw_remove_member(p_school_id uuid, p_user_id uuid)
returns boolean language plpgsql security definer set search_path = ''
as $$
declare v_uid uuid := (select auth.uid()); v_removed integer;
begin
  if not exists(select 1 from public.qw_members
      where school_id=p_school_id and user_id=v_uid and role='owner') then
    raise exception 'OWNER_ONLY'; end if;
  delete from public.qw_members where school_id=p_school_id
     and user_id=p_user_id and role='editor';
  get diagnostics v_removed = row_count;
  return v_removed > 0;
end;
$$;

-- منع استخدام الدوال العامة من غير المستخدمين المسجلين.
revoke all on function public.qw_is_member(uuid) from PUBLIC, anon;
revoke all on function public.qw_create_school(text) from PUBLIC, anon;
revoke all on function public.qw_save_data(uuid,bigint,jsonb) from PUBLIC, anon;
revoke all on function public.qw_create_invite(uuid) from PUBLIC, anon;
revoke all on function public.qw_join_school(text) from PUBLIC, anon;
revoke all on function public.qw_list_team(uuid) from PUBLIC, anon;
revoke all on function public.qw_remove_member(uuid,uuid) from PUBLIC, anon;
grant execute on function public.qw_is_member(uuid),public.qw_create_school(text),
  public.qw_save_data(uuid,bigint,jsonb),public.qw_create_invite(uuid),
  public.qw_join_school(text),public.qw_list_team(uuid),
  public.qw_remove_member(uuid,uuid) to authenticated;

-- تفعيل التحديثات اللحظية إذا لم تكن الجدول ضمن publication بعد.
do $$
begin
  if exists(select 1 from pg_publication where pubname='supabase_realtime')
     and not exists(select 1 from pg_publication_tables
       where pubname='supabase_realtime' and schemaname='public' and tablename='qw_data') then
    alter publication supabase_realtime add table public.qw_data;
  end if;
end $$;
