#ifndef THREAD_POOL_MGR_H
#define THREAD_POOL_MGR_H

#include <cstddef>

#include "thread_pool.h"

class ThreadPoolMgr {
public:
  /**
  Build an instance of ThreadPoolMgr
  */
  ThreadPoolMgr();

  /**
  Destructor for ThreadPoolMgr
  */
  ~ThreadPoolMgr();

  /**
  Get the thread pool managed by the thread pool manager
  */
  ThreadPool &thread_pool() const;

  /**
  Set the number of threads to be used by the thread pool
  */
  static void SetThreadCount(std::size_t threads);

  /**
  This method is to be used explicitly by tests.
  */
  static void SetPhysThreadCount(std::size_t threads);

  /**
  Get the number of threads used by the thread pool
  */
  static std::size_t GetThreadCount();

private:
  /**
  Reference count to manage lifetime of the static thread pool
  */
  static std::size_t ref_count_;
};

#endif