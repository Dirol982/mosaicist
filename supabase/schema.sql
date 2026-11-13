-- Реестр сайтов студии: схема для Supabase.
-- Выполнить один раз в SQL Editor проекта (или через Management API).
-- Две роли: contractor (подрядчик) и studio (студия). Доступ только по приглашению.

-- Участники и приглашения
create table if not exists public.members (
  user_id    uuid primary key references auth.users on delete cascade,
  email      text not null,
  name       text not null default '',
  role       text not null check (role in ('contractor','studio')),
  created_at timestamptz not null default now()
);
create table if not exists public.invites (
  email      text primary key,
  role       text not null check (role in ('contractor','studio')),
  name       text not null default '',
  created_at timestamptz not null default now()
);

-- Данные трекера: документы по коллекциям (sites, tasks, studio, comments — видны студии;
-- internal, siteInternal, history — только подрядчику)
create table if not exists public.docs (
  collection text not null,
  id         text not null,
  data       jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  updated_by uuid default auth.uid(),
  primary key (collection, id)
);

create or replace function public.my_role() returns text
language sql stable security definer set search_path = public as $$
  select role from public.members where user_id = auth.uid()
$$;

create or replace function public.studio_can_read(c text) returns boolean
language sql immutable as $$ select c in ('sites','tasks','studio','comments') $$;
create or replace function public.studio_can_write(c text) returns boolean
language sql immutable as $$ select c in ('studio','comments') $$;

alter table public.members enable row level security;
alter table public.invites enable row level security;
alter table public.docs    enable row level security;

drop policy if exists members_read  on public.members;
drop policy if exists members_admin on public.members;
create policy members_read  on public.members for select using (public.my_role() is not null);
create policy members_admin on public.members for all    using (public.my_role() = 'contractor') with check (public.my_role() = 'contractor');

drop policy if exists invites_admin on public.invites;
create policy invites_admin on public.invites for all using (public.my_role() = 'contractor') with check (public.my_role() = 'contractor');

drop policy if exists docs_read   on public.docs;
drop policy if exists docs_insert on public.docs;
drop policy if exists docs_update on public.docs;
drop policy if exists docs_delete on public.docs;
create policy docs_read on public.docs for select using (
  public.my_role() = 'contractor' or (public.my_role() = 'studio' and public.studio_can_read(collection)));
create policy docs_insert on public.docs for insert with check (
  public.my_role() = 'contractor' or (public.my_role() = 'studio' and public.studio_can_write(collection)));
create policy docs_update on public.docs for update
  using      (public.my_role() = 'contractor' or (public.my_role() = 'studio' and public.studio_can_write(collection)))
  with check (public.my_role() = 'contractor' or (public.my_role() = 'studio' and public.studio_can_write(collection)));
create policy docs_delete on public.docs for delete using (public.my_role() = 'contractor');

-- Слияние полей документа (как update в трекере); права проверяет RLS
create or replace function public.doc_merge(p_collection text, p_id text, p_patch jsonb) returns void
language sql security invoker set search_path = public as $$
  update public.docs set data = data || p_patch, updated_at = now(), updated_by = auth.uid()
  where collection = p_collection and id = p_id
$$;

-- Регистрация только по приглашению: без приглашения аккаунт не создаётся
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
declare inv public.invites;
begin
  select * into inv from public.invites where lower(email) = lower(new.email);
  if not found then
    raise exception 'Нет приглашения для %', new.email;
  end if;
  insert into public.members (user_id, email, name, role) values (new.id, new.email, inv.name, inv.role)
    on conflict (user_id) do nothing;
  delete from public.invites where lower(email) = lower(new.email);
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- Обновления в реальном времени
alter table public.docs replica identity full;
do $$ begin
  alter publication supabase_realtime add table public.docs;
exception when duplicate_object then null; end $$;
