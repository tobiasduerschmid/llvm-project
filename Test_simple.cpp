class Rate
 {
 public:
   Rate(double frequency);
 
   bool sleep();
 
   void reset();
 
   int cycleTime();
 
   int expectedCycleTime() { return expected_cycle_time_; }
 
 private:
   int start_;
   int expected_cycle_time_, actual_cycle_time_;
 };

void sleep(int r) {
  for(int i = 0; i < r; i++);
}

int main(int argc, char** argv) {
  int x = 10;
  int y = 20;
  if (y < argc) {
  //  sleep(10);
    Rate r(10);
  }
}