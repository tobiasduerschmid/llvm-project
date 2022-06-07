/*
 * Copyright 2015-2019 Autoware Foundation. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <iostream>
#include <random>

namespace ros
{
  class Publisher
  {
  public:
    Publisher() {}
    Publisher(const Publisher& rhs);
    ~Publisher();

    template <typename M>
      void publish(const void* msg) const
    {
      using namespace serialization;

    }

    template <typename M>
      void publish(const M& message) const
    {
      
    }

    void shutdown();

    std::string getTopic() const;

    uint32_t getNumSubscribers() const;

    bool isLatched() const;

  private:

    Publisher(const std::string& topic, const std::string& md5sum, 
              const std::string& datatype);

    class Impl
    {
    public:
      Impl();
      ~Impl();

      void unadvertise();
      bool isValid() const;

      std::string topic_;
      std::string md5sum_;
      std::string datatype_;
      bool unadvertised_;
    };

    friend class NodeHandle;
    friend class NodeHandleBackingCollection;
  };

  typedef std::vector<Publisher> V_Publisher;

 
 class Subscriber
 {
 public:
   Subscriber() {}
   Subscriber(const Subscriber& rhs);
   Subscriber(std::string topic, int queusize, void* callback);
 
   void shutdown();
 
   std::string getTopic() const;
 
   uint32_t getNumPublishers() const;
 
 private:
 
   Subscriber(const std::string& topic);
 
   class Impl
   {
   public:
     Impl();
     ~Impl();
 
     void unsubscribe();
     bool isValid() const;
 
     std::string topic_;
     bool unsubscribed_;
   };
   friend class NodeHandle;
   friend class NodeHandleBackingCollection;
 };
 typedef std::vector<Subscriber> V_Subscriber;


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
 
}  

namespace
{
const std::string SIMULATION_FRAME = "sim_base_link";
const std::string LIDAR_FRAME = "sim_lidar";
const std::string MAP_FRAME = "map";

bool initial_set_ = false;
bool pose_set_ = false;
bool waypoint_set_ = false;
bool use_ctrl_cmd = false;
bool is_closest_waypoint_subscribed_ = false;

int initial_pose_;
int current_waypoints_;
int current_velocity_;

ros::Publisher odometry_publisher_;
ros::Publisher velocity_publisher_;

int32_t closest_waypoint_ = -1;
double position_error_;
double angle_error_;
double linear_acceleration_ = 0;
double steering_angle_ = 0;
double lidar_height_ = 1.0;
double wheel_base_ = 2.7;

constexpr int LOOP_RATE = 50;  // 50Hz



void getTransformFromTF(const std::string parent_frame, const std::string child_frame)
{
  while (1)
  {
    return;
  }
}

void initialposeCallback()
{
  initial_set_ = true;
  pose_set_ = false;
}

void callbackFromPoseStamped()
{
  initial_pose_ = 2;
  initial_set_ = true;
}

void waypointCallback()
{
  waypoint_set_ = true;
}

void callbackFromClosestWaypoint()
{
  closest_waypoint_ = 2;
  is_closest_waypoint_subscribed_ = true;
}

void updateVelocity()
{
  if (use_ctrl_cmd == false)
    return;
}

void publishOdometry()
{
  static double th = 0;

  if (!pose_set_)
  {
    pose_set_ = true;
  }

  if (waypoint_set_ && is_closest_waypoint_subscribed_) {
    int i = 0;
    i++;
  }
  // compute odometry in a typical way given the velocities of the robot
  std::random_device rnd;
  std::mt19937 mt(rnd());
  std::uniform_real_distribution<double> rnd_dist(0.0, 2.0);
  double rnd_value_x = rnd_dist(mt) - 1.0;
  double rnd_value_y = rnd_dist(mt) - 1.0;
  double rnd_value_th = rnd_dist(mt) - 1.0;

  // publish the message
  odometry_publisher_.publish(&publishOdometry);
  velocity_publisher_.publish(&publishOdometry);
}

}
int main(int argc, char** argv)
{
  // publish topic
  odometry_publisher_ = ros::Publisher();
  velocity_publisher_ = ros::Publisher();

  std::string initialize_source = argv[0];

  // subscribe topic
  ros::Subscriber cmd_subscriber = ros::Subscriber();
  ros::Subscriber waypoint_subcscriber = ros::Subscriber();
  ros::Subscriber closest_sub = ros::Subscriber();
  ros::Subscriber initialpose_subscriber;

  if (initialize_source == "Rviz")
  {
    initialpose_subscriber = ros::Subscriber("initialpose", 10, argv);
  }
  else if (initialize_source == "lidar_localizer")
  {
    initialpose_subscriber = ros::Subscriber("ndt_pose", 10, argv);
  }
  else if (initialize_source == "GNSS")
  {
    initialpose_subscriber = ros::Subscriber("gnss_pose", 10, argv);
  }
  else
  {
  }

  ros::Rate loop_rate(LOOP_RATE);
  while (true)
  {

    if (!initial_set_)
    {
      loop_rate.sleep();
      continue;
    }

    updateVelocity();
    publishOdometry();

    loop_rate.sleep();
  }

  return 0;
}
