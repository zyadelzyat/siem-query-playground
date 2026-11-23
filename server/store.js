import {get, put, list, del, BlobPreconditionFailedError} from '@vercel/blob';
export const store = {
 async read(path) {
  const result = await get(path, {access:'private', useCache:false});
  return result ? new Response(result.stream).json() : null;
 },
 async write(path, value, overwrite=false, ttlDays) {
  try {
   await put(path, JSON.stringify(value), {access:'private',addRandomSuffix:false,allowOverwrite:overwrite,contentType:'application/json',...(ttlDays?{ttlDays}:{})});
   return true;
  } catch(error) {
   // A concurrent create of the same immutable record is an idempotent success.
   if (!overwrite && (error instanceof BlobPreconditionFailedError || /already exists/i.test(error.message))) return false;
   throw error;
  }
 },
 async paths(prefix) {
  const entries=[]; let cursor;
  do {const page=await list({prefix,limit:1000,...(cursor?{cursor}:{})});entries.push(...page.blobs.map(b=>b.pathname));cursor=page.hasMore?page.cursor:undefined;} while(cursor);
  return entries;
 },
 async remove(path) { await del(path); }
};
