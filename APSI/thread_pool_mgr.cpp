#include "thread_pool_mgr.h"
#include <mutex>
#include <memory>
#include <thread>
#include <stdexcept>

using namespace std;

// Static variable definition
size_t ThreadPoolMgr::ref_count_ = 0;

// Internal variables only visible in this translation unit
namespace {
    mutex tp_mutex;
    size_t thread_count = thread::hardware_concurrency();
    size_t phys_thread_count = thread::hardware_concurrency();
    unique_ptr<ThreadPool> thread_pool_;
}

ThreadPoolMgr::ThreadPoolMgr() {
    unique_lock<mutex> lock(tp_mutex);
    if (ref_count_ == 0) {
        thread_pool_ = make_unique<ThreadPool>(phys_thread_count);
    }
    ref_count_++;
}

ThreadPoolMgr::~ThreadPoolMgr() {
    unique_lock<mutex> lock(tp_mutex);
    ref_count_--;
    if (ref_count_ == 0) {
        thread_pool_ = nullptr;
    }
}

ThreadPool& ThreadPoolMgr::thread_pool() const {
    if (!thread_pool_) {
        throw runtime_error("Thread pool is not available");
    }
    return *thread_pool_;
}

void ThreadPoolMgr::SetThreadCount(size_t threads) {
    unique_lock<mutex> lock(tp_mutex);
    thread_count = threads != 0 ? threads : thread::hardware_concurrency();
    phys_thread_count = thread_count;
    if (thread_pool_) {
        thread_pool_->set_pool_size(phys_thread_count);
    }
}

void ThreadPoolMgr::SetPhysThreadCount(size_t threads) {
    unique_lock<mutex> lock(tp_mutex);
    phys_thread_count = threads != 0 ? threads : thread::hardware_concurrency();
    if (thread_pool_) {
        thread_pool_->set_pool_size(phys_thread_count);
    }
}

size_t ThreadPoolMgr::GetThreadCount() {
    return thread_count;
}